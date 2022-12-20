//! Signed-data content type [RFC 5652 § 5.1](https://datatracker.ietf.org/doc/html/rfc5652#section-5.1)

use der::{
    asn1::{OctetStringRef, SetOfVec},
    AnyRef, Choice, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence,
    Tag, TagNumber, ValueOrd, Writer,
};
use spki::{AlgorithmIdentifierRef, ObjectIdentifier};
use x509_cert::certificate::Certificate;

/// Syntax version of the `signed-data` content type.
///
/// ```asn1
/// Version ::= Integer
/// ```
///
/// Versions `1` through `5` are supported by this library.
/// See [RFC 5652 § 5.1](https://datatracker.ietf.org/doc/html/rfc5652#section-5.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Version {
    /// version 1.
    V1 = 1,

    /// version 2.
    V2 = 2,

    /// version 3.
    V3 = 3,

    /// version 4.
    V4 = 4,

    /// version 5.
    V5 = 5,
}

impl FixedTag for Version {
    const TAG: Tag = Tag::Integer;
}

impl From<Version> for u8 {
    fn from(version: Version) -> Self {
        version as u8
    }
}

impl TryFrom<u8> for Version {
    type Error = der::Error;
    fn try_from(byte: u8) -> der::Result<Version> {
        match byte {
            1 => Ok(Version::V1),
            2 => Ok(Version::V2),
            3 => Ok(Version::V3),
            4 => Ok(Version::V4),
            5 => Ok(Version::V5),
            _ => Err(Self::TAG.value_error()),
        }
    }
}

impl<'a> DecodeValue<'a> for Version {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Version> {
        Version::try_from(u8::decode_value(reader, header)?)
    }
}

impl EncodeValue for Version {
    fn value_len(&self) -> der::Result<Length> {
        u8::from(*self).value_len()
    }

    fn encode_value(&self, writer: &mut dyn Writer) -> der::Result<()> {
        u8::from(*self).encode_value(writer)
    }
}

type DigestAlgorithmIdentifier<'a> = AlgorithmIdentifierRef<'a>;

type ContentType = ObjectIdentifier;

/// ```asn1
/// EncapsulatedContentInfo ::= SEQUENCE {
///   eContentType ContentType,
///   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
///
/// ContentType ::= OBJECT IDENTIFIER
/// ```
#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence)]
pub struct EncapsulatedContentInfo<'a> {
    /// the content type for `content`.
    pub content_type: ContentType,

    // NOTE: This allows for both the `eContent [0] EXPLICIT OCTET STRING` form,
    // as well as the `content [0] EXPLICIT ANY DEFINED BY contentType` form,
    // as permitted in RFC 5652 § 5.2.1.
    /// the content itself.
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub content: Option<AnyRef<'a>>,
}

/// ```asn1
/// CertificateChoices ::= CHOICE {
///   certificate Certificate,
///   extendedCertificate [0] IMPLICIT ExtendedCertificate, -- Obsolete
///   v1AttrCert [1] IMPLICIT AttributeCertificateV1,       -- Obsolete
///   v2AttrCert [2] IMPLICIT AttributeCertificateV2,
///   other [3] IMPLICIT OtherCertificateFormat }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Choice, ValueOrd)]
pub enum CertificateChoices<'a> {
    Certificate(Certificate<'a>),
    // ExtendedCertificate,
    // V1AttrCert,
    // V2AttrCert,
    // Other,
}

/// Signed-data content type [RFC 5652 § 5.1](https://datatracker.ietf.org/doc/html/rfc5652#section-5.1)
///
/// ```asn1
/// SignedData ::= SEQUENCE {
///   version CMSVersion,
///   digestAlgorithms DigestAlgorithmIdentifiers,
///   encapContentInfo EncapsulatedContentInfo,
///   certificates [0] IMPLICIT CertificateSet OPTIONAL,
///   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
///   signerInfos SignerInfos }
/// ```
///
/// The signed-data content type consists of signed data of any type.
/// The data may be signed for multiple times, with multiple independent
/// verification paths defined through the specified certificates (and
/// multiple independent revocation paths defined through the specified
/// CRLs).
///
/// The fields of `SignedDataContent` have the following meanings:
///   - [`version`](SignedDataContent::version) is the syntax version number
///   - [`digest_algorithms`](SignedDataContent::digest_algorithms) is a collection
///     of digest algorithm identifiers
///   - [`encapsulated_content_info`](SignedDataContent::encapsulated_content_info)
///     is the encapsulated signed content
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SignedDataContent<'a> {
    /// the syntax version number.
    pub version: Version,

    /// the message digest algorithm identifiers.
    pub digest_algorithms: SetOfVec<DigestAlgorithmIdentifier<'a>>,

    /// the signed content.
    pub encapsulated_content_info: EncapsulatedContentInfo<'a>,

    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub certificates: Option<SetOfVec<CertificateChoices<'a>>>,
    // #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    // pub crls: (),

    // pub signer_infos: (),
}
