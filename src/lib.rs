//! AbuseIPDB API Client.
//! 
//! ```rust
//! use abuseipdb::Client;
//! use std::net::Ipv4Addr;
//! 
//! async fn example() {
//!     let my_ip = Ipv4Addr::new(127, 0, 0, 1).into();
//!     let client = Client::new("<API-KEY>");
//!     let response = client.check(my_ip, None, false).await.unwrap();
//!     println!("abuseConfidenceScore: {}", response.data.abuse_confidence_score);
//! }
//! ```

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use chrono::prelude::{DateTime, NaiveDateTime, Utc};
use jsonapi::api::JsonApiError;
use reqwest::header::{self, HeaderMap};
use reqwest::{RequestBuilder, StatusCode, Url};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_repr::{Deserialize_repr, Serialize_repr};
use serde_urlencoded::to_string as serialize_url_query;

pub const DEFAULT_BASE_URL: &str = "https://api.abuseipdb.com/api/v2/";
pub const DEFAULT_USER_AGENT: &str = concat!("rust-abuseipdb-client/", env!("CARGO_PKG_VERSION"));

///////////////////////////////////////////////////////////////////////////////
// Common

/// Represents a failure while making a request to AbuseIPDB.
#[derive(Debug)]
pub enum Error {
    InvalidBody,
    InvalidHeaders,
    Api(ApiError),
    Client(reqwest::Error),
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Self::Client(err)
    }
}

/// Represents an error returned by AbuseIPDB via the API.
#[derive(Debug)]
pub struct ApiError {
    pub rate_limit: RateLimit,
    pub retry_after: Option<Duration>,
    pub errors: Vec<JsonApiError>,
}

/// AbuseIPDB attack categories.
#[derive(Debug, Clone, Serialize_repr, Deserialize_repr, PartialEq)]
#[repr(u8)]
pub enum Category {
    /// Fraudulent orders.
    FraudOrder = 3,
    /// Participating in distributed denial-of-service (usually part of botnet).
    DdosAttack = 4,
    /// FTP Brute-Force
    FtpBruteForce = 5,
    /// Oversized IP packet.
    PingOfDeath = 6,
    /// Phishing websites and/or email.
    Phishing = 7,
    /// Fraud VoIP
    FraudVoip = 8,
    /// Open proxy, open relay, or Tor exit node.
    OpenProxy = 9,
    /// Comment/forum spam, HTTP referer spam, or other CMS spam.
    WebSpam = 10,
    /// Spam email content, infected attachments, and phishing emails.
    /// Note: Limit comments to only relevent information (instead of log dumps)
    /// and be sure to remove PII if you want to remain anonymous.
    EmailSpam = 11,
    /// CMS blog comment spam.
    BlogSpam = 12,
    /// VPN IP - Conjunctive category.
    VpnIp = 13,
    /// Scanning for open ports and vulnerable services.
    PortScan = 14,
    /// Hacking
    Hacking = 15,
    /// Attempts at SQL injection.
    SqlInjection = 16,
    /// Email sender spoofing.
    Spoofing = 17,
    /// Brute-force attacks on webpage logins and services
    /// like SSH, FTP, SIP, SMTP, RDP, etc.
    /// This category is seperate from DDoS attacks.
    BruteForceCredential = 18,
    /// Webpage scraping (for email addresses, content, etc) and crawlers that
    /// do not honor robots.txt. Excessive requests and user agent spoofing
    /// can also be reported here.
    BadWebBot = 19,
    /// Host is likely infected with malware and being used for other
    /// attacks or to host malicious content. The host owner may not be aware
    /// of the compromise. This category is often used in combination with
    /// other attack categories.
    ExploitedHost = 20,
    /// Attempts to probe for or exploit installed web applications such
    /// as a CMS like WordPress/Drupal, e-commerce solutions, forum software,
    /// phpMyAdmin and various other software plugins/solutions.
    WebAppAttack = 21,
    /// Secure Shell (SSH) abuse. Use this category in combination with more
    /// specific categories.
    SshAbuse = 22,
    /// Abuse was targeted at an "Internet of Things" type device.
    /// Include information about what type of device was targeted
    /// in the comments.
    IotTargeted = 23,
}

///////////////////////////////////////////////////////////////////////////////
// Requests and Responses

trait Request {
    type Response: DeserializeOwned;

    fn into_builder(self, client: &Client) -> RequestBuilder;
}

/// Wrapper type for successful API responses with rate limit
/// and meta information.
#[derive(Debug)]
pub struct Response<T> {
    pub data: T,
    pub meta: Option<HashMap<String, Value>>,
    pub rate_limit: RateLimit,
}

/// The rate limit information returned from a request to AbuseIPDB.
#[derive(Debug)]
pub struct RateLimit {
    /// Your daily limit.
    pub limit: u32,
    /// Remaining requests available for this endpoint.
    pub remaining: u32,
    /// The timestamp for the daily limit reset.
    pub reset_at: Option<DateTime<Utc>>,
}

impl RateLimit {
    fn from_headers(header_map: &HeaderMap) -> Result<Self, Error> {
        let limit = parse_i64_header(&header_map, "x-ratelimit-limit")?
            .ok_or(Error::InvalidHeaders)? as u32;
        let remaining = parse_i64_header(&header_map, "x-ratelimit-remaining")?
            .ok_or(Error::InvalidHeaders)? as u32;
        let reset_at = parse_i64_header(&header_map, "x-ratelimit-reset")?
            .map(|ts| DateTime::from_utc(NaiveDateTime::from_timestamp(ts, 0), Utc));
        Ok(RateLimit {
            limit,
            remaining,
            reset_at,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AddressAbuse {
    #[serde(rename = "ipAddress")]
    pub ip_addr: IpAddr,
    #[serde(rename = "abuseConfidenceScore")]
    pub abuse_confidence_score: u8,
}

///////////////////////////////////////////////////////////////////////////////
// CHECK

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Check {
    #[serde(rename = "ipAddress")]
    pub ip_addr: IpAddr,
    #[serde(rename = "isPublic")]
    pub is_public: bool,
    /// The `is_whitelisted` property reflects whether the IP is spotted in any AbuseDB whitelists.
    ///
    /// The whitelists give the benefit of the doubt to many IPs, so it generally should not be
    /// used as a basis for action. The `abuse_confidence_score` is a better basis for action,
    /// because it is nonbinary and allows for nuance. The `is_whitelisted` property may be null
    /// if a whitelist lookup was not performed.
    #[serde(rename = "isWhitelisted")]
    pub is_whitelisted: Option<bool>,
    #[serde(rename = "abuseConfidenceScore")]
    pub abuse_confidence_score: u32,
    #[serde(rename = "countryCode")]
    pub country_code: Option<String>,
    #[serde(rename = "countryName")]
    pub country_name: Option<String>,
    #[serde(rename = "usageType")]
    pub usage_type: String,
    pub isp: String,
    pub domain: Option<String>,
    #[serde(rename = "totalReports")]
    pub total_reports: u64,
    #[serde(rename = "numDistinctUsers")]
    pub num_distinct_users: u64,
    #[serde(rename = "lastReportedAt")]
    pub last_reported_at: DateTime<Utc>,
    pub reports: Option<Vec<CheckReport>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CheckReport {
    #[serde(rename = "reportedAt")]
    pub reported_at: DateTime<Utc>,
    pub comment: Option<String>,
    pub categories: Vec<Category>,
    #[serde(rename = "reporterId")]
    pub reporter_id: u64,
    #[serde(rename = "reporterCountryCode")]
    pub reporter_country_code: String,
    #[serde(rename = "reporterCountryName")]
    pub reporter_country_name: String,
}

// Verbose flag if `false`, will exclude reports and the country name field.
#[derive(Serialize)]
struct CheckRequest {
    pub verbose: bool,
    #[serde(rename = "ipAddress")]
    pub ip_addr: IpAddr,
    #[serde(rename = "maxAgeInDays")]
    pub max_age_in_days: Option<u16>,
}

impl Request for CheckRequest {
    type Response = Check;

    fn into_builder(self, client: &Client) -> RequestBuilder {
        client.inner.get(client.endpoint("check", self))
    }
}

///////////////////////////////////////////////////////////////////////////////
// BLACKLIST

pub type Blacklist = Vec<AddressAbuse>;

#[derive(Serialize)]
struct BlacklistRequest {
    #[serde(rename = "confidenceMinimum")]
    pub confidence_min: Option<u8>,
    pub limit: Option<u32>,
    #[serde(rename = "self")]
    pub for_self: bool,
}

impl Request for BlacklistRequest {
    type Response = Blacklist;

    fn into_builder(self, client: &Client) -> RequestBuilder {
        client.inner.get(client.endpoint("blacklist", self))
    }
}

///////////////////////////////////////////////////////////////////////////////
// REPORT

#[derive(Serialize)]
struct ReportRequest<'a> {
    #[serde(rename = "ip")]
    pub ip_addr: IpAddr,
    pub categories: &'a [Category],
    pub comment: Option<&'a str>,
}

impl<'a> Request for ReportRequest<'a> {
    type Response = AddressAbuse;

    fn into_builder(self, client: &Client) -> RequestBuilder {
        client.inner.post(client.endpoint("report", self))
    }
}

///////////////////////////////////////////////////////////////////////////////
// CHECK-BLOCK

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockCheck {
    #[serde(rename = "networkAddress")]
    pub network_address: IpAddr,
    pub netmask: IpAddr,
    #[serde(rename = "minAddress")]
    pub min_address: IpAddr,
    #[serde(rename = "maxAddress")]
    pub max_address: IpAddr,
    #[serde(rename = "numPossibleHosts")]
    pub num_possible_hosts: u64,
    #[serde(rename = "addressSpaceDesc")]
    pub address_space_desc: String,
    #[serde(rename = "reportedAddress")]
    pub reported_address: Vec<BlockCheckReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockCheckReport {
    #[serde(rename = "ipAddress")]
    pub ip_addr: IpAddr,
    #[serde(rename = "numReports")]
    pub num_reports: u64,
    #[serde(rename = "mostRecentReport")]
    pub most_recent_report: DateTime<Utc>,
    #[serde(rename = "abuseConfidenceScore")]
    pub abuse_confidence_score: u8,
    #[serde(rename = "countryCode")]
    pub country_code: Option<String>,
}

#[derive(Serialize)]
struct CheckBlockRequest<'a> {
    pub network: &'a str,
    #[serde(rename = "maxAgeInDays")]
    pub max_age_in_days: Option<u16>,
}

impl<'a> Request for CheckBlockRequest<'a> {
    type Response = BlockCheck;

    fn into_builder(self, client: &Client) -> RequestBuilder {
        client.inner.get(client.endpoint("check-block", self))
    }
}

///////////////////////////////////////////////////////////////////////////////
// Client

/// The AbuseIPDB client.
pub struct Client {
    base_url: Url,
    inner: reqwest::Client,
    user_agent: Cow<'static, str>,
    api_key: Option<Cow<'static, str>>,
}

impl Client {
    /// Create a new AbuseIPDB client with the given API key and 
    /// default settings.
    pub fn new<S: Into<String>>(api_key: S) -> Self {
        Self::builder().api_key(api_key.into()).build()
    }

    /// Returns a AbuseIPDB client builder.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Queries AbuseIPDB given a IP address.
    ///
    /// The check endpoint accepts a single IP address (v4 or v6). 
    /// Optionally you may set the `max_age_in_days` parameter to only 
    /// return reports within the last x amount of days.
    pub async fn check(
        &self,
        ip_addr: IpAddr,
        max_age_in_days: Option<u16>,
        verbose: bool,
    ) -> Result<Response<Check>, Error> {
        self.request(CheckRequest {
            ip_addr,
            max_age_in_days,
            verbose,
        })
        .await
    }

    /// Queries AbuseIPDB given a subnet.
    ///
    /// The check-block endpoint accepts a subnet (v4 or v6) 
    /// denoted with CIDR notation.
    pub async fn check_block(
        &self,
        network: &str,
        max_age_in_days: Option<u16>,
    ) -> Result<Response<BlockCheck>, Error> {
        self.request(CheckBlockRequest {
            network,
            max_age_in_days,
        })
        .await
    }

    /// Queries AbuseIPDB for the blacklist.
    ///
    /// The blacklist is the culmination of all of the valiant reporting 
    /// by AbuseIPDB users. It's a list of the most reported IP addresses.
    pub async fn blacklist(
        &self,
        confidence_min: Option<u8>,
        limit: Option<u32>,
        for_self: bool,
    ) -> Result<Response<Blacklist>, Error> {
        self.request(BlacklistRequest {
            confidence_min,
            limit,
            for_self,
        })
        .await
    }

    /// Reports an IP address to AbuseIPDB.
    ///
    /// At least one category is required.
    pub async fn report(
        &self,
        ip_addr: IpAddr,
        categories: &[Category],
        comment: Option<&str>,
    ) -> Result<Response<AddressAbuse>, Error> {
        self.request(ReportRequest {
            ip_addr,
            categories,
            comment,
        })
        .await
    }
    

    async fn request<R>(&self, req: R) -> Result<Response<R::Response>, Error>
    where
        R: Request,
    {
        self.do_request(req.into_builder(&self)).await
    }

    async fn do_request<T: DeserializeOwned>(
        &self,
        req: RequestBuilder,
    ) -> Result<Response<T>, Error> {
        #[derive(Deserialize)]
        struct JsonApiDocument<D> {
            data: Option<D>,
            meta: Option<HashMap<String, Value>>,
            errors: Option<Vec<JsonApiError>>,
        }
        // Add the API key to the request if set.
        let req = match self.api_key {
            Some(ref api_key) => req.header("Key", api_key.as_ref()),
            None => req,
        };
        // Set the request user agent and set accept to json mime
        // and then send.
        let res = req
            .header(header::ACCEPT, "application/json")
            .header(header::USER_AGENT, self.user_agent.as_ref())
            .send()
            .await?;
        // Extract the rate limit information from the response headers.
        let res_status = res.status();
        let rate_limit = RateLimit::from_headers(res.headers())?;
        let retry_after_opt = parse_i64_header(res.headers(), header::RETRY_AFTER.as_str())?;
        // Deserialize the JSON document body.
        let JsonApiDocument { errors, data, meta } = res.json().await?;
        // Handle the parsed JSON response.
        match (data, errors) {
            (Some(data), None) => Ok(Response {
                meta,
                data,
                rate_limit,
            }),
            (None, Some(errors)) => {
                let retry_after = match res_status {
                    StatusCode::TOO_MANY_REQUESTS => {
                        let retry_after_secs = retry_after_opt.ok_or(Error::InvalidHeaders)?;
                        Some(Duration::from_secs(retry_after_secs as u64))
                    }
                    _ => None,
                };
                let err = ApiError {
                    errors,
                    rate_limit,
                    retry_after,
                };
                Err(Error::Api(err))
            }
            _ => Err(Error::InvalidBody),
        }
    }

    ///////////////////////////////////////////////////////////////////////////////
    // Helpers

    fn endpoint<P: Serialize>(&self, endpoint: &str, params: P) -> Url {
        let mut url = self.base_url.join(endpoint).unwrap();
        let query = serialize_url_query(params).unwrap();
        url.set_query(Some(query.as_str()));
        url
    }
}

///////////////////////////////////////////////////////////////////////////////
// Client Builder

/// A builder to create a configured AbuseIPDB client.
#[derive(Debug, Clone)]
pub struct ClientBuilder {
    inner: reqwest::Client,
    api_key: Option<Cow<'static, str>>,
    user_agent: Cow<'static, str>,
    base_url: Url,
}

impl ClientBuilder {
    /// Create the client builder with the default HTTP client.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates the client builder, given a pre-existing HTTP client.
    pub fn with_client(client: reqwest::Client) -> Self {
        Self {
            api_key: None,
            inner: client,
            user_agent: DEFAULT_USER_AGENT.into(),
            base_url: Url::parse(DEFAULT_BASE_URL).unwrap(),
        }
    }

    /// Sets the base URL for the AbuseIPDB API.
    pub fn base_url<S>(mut self, base_url: Url) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Set the user agent the client will use when making a
    /// request to AbuseIPDB.
    pub fn user_agent<S>(mut self, user_agent: S) -> Self
    where
        S: Into<Cow<'static, str>>,
    {
        self.user_agent = user_agent.into();
        self
    }

    /// Sets the API key to be used to authenticate when 
    /// making a request AbuseIPDB.
    pub fn api_key<S>(mut self, api_key: S) -> Self
    where
        S: Into<Cow<'static, str>>,
    {
        self.api_key = Some(api_key.into());
        self
    }

    /// Consumes the client builder and returns the built
    /// AbuseIPDB client.
    pub fn build(self) -> Client {
        Client {
            inner: self.inner,
            api_key: self.api_key,
            base_url: self.base_url,
            user_agent: self.user_agent,
        }
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::with_client(reqwest::Client::new())
    }
}

///////////////////////////////////////////////////////////////////////////////
// Helpers

fn parse_i64_header(header_map: &HeaderMap, key: &str) -> Result<Option<i64>, Error> {
    header_map
        .get(key)
        .map(|val| {
            let s = val.to_str().map_err(|_| Error::InvalidHeaders)?;
            i64::from_str_radix(s, 10).map_err(|_| Error::InvalidHeaders)
        })
        .transpose()
}
