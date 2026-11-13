---
title: Use of Hybrid Public-Key Encryption (HPKE) with CBOR Object Signing and Encryption (COSE)
abbrev: COSE HPKE
docname: draft-ietf-cose-hpke-latest
category: std

ipr: pre5378Trust200902
area: Security
workgroup: COSE
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
-
  ins: H. Tschofenig
  name: Hannes Tschofenig
  organization: University of the Bundeswehr Munich
  abbrev: UniBw M.
  city: Neubiberg
  region: Bavaria
  country: Germany
  code: 85577
  email: hannes.tschofenig@gmx.net
-
  ins: M. Jones
  name: Michael B. Jones
  role: editor
  organization: Self-Issued Consulting
  email: michael_b_jones@hotmail.com
  uri: https://self-issued.info/
  country: United States
-
  ins: O. Steele
  name: Orie Steele
  organization: Tradeverifyd
  email: orie@or13.io
  country: United States
-
  ins: D. Ajitomi
  name: Daisuke Ajitomi
  organization: bibital LLC
  email: dajiaji@gmail.com
  country: Japan
-
  ins: L. Lundblade
  name: Laurence Lundblade
  organization: Security Theory LLC
  email: lgl@securitytheory.com
  country: United States

normative:
  RFC2119:
  RFC8174:
  RFC8610:
  RFC8949:
  RFC9052:
  RFC9053:
  I-D.ietf-hpke-hpke:

informative:
  RFC8937:
  RFC9864:
  I-D.irtf-cfrg-dnhpke:
  I-D.ietf-lamps-cms-cek-hkdf-sha256:
  HPKE-IANA:
     author:
        org: IANA
     title: Hybrid Public Key Encryption (HPKE) IANA Registry
     target: https://www.iana.org/assignments/hpke/hpke.xhtml
     date: October 2023

--- abstract

This specification defines hybrid public-key encryption (HPKE) for use with
CBOR Object Signing and Encryption (COSE). HPKE offers a variant of
public-key encryption of arbitrary-sized plaintexts for a recipient public key.

HPKE is a general encryption framework utilizing an asymmetric key encapsulation
mechanism (KEM), a key derivation function (KDF), and an Authenticated Encryption
with Associated Data (AEAD) algorithm.

This document defines the use of HPKE with COSE. Authentication for HPKE in COSE is
provided by COSE-native security mechanisms or by the pre-shared key authenticated
variant of HPKE.


--- middle

#  Introduction

Hybrid public-key encryption (HPKE) {{I-D.ietf-hpke-hpke}} is a scheme that
provides public key encryption of arbitrary-sized plaintexts given a
recipient's public key.

This document defines the use of HPKE with COSE ({{RFC9052}}, {{RFC9053}})
with the single-shot APIs defined in {{Section 6 of I-D.ietf-hpke-hpke}}. Multiple
invocations of Open() / Seal() on the same context, as discussed in
{{Section 9.7.1 of I-D.ietf-hpke-hpke}} are not supported.

Algorithm identifiers follow a ciphersuite scheme in which a single COSE algorithm ID maps to the three algorithm IDs required for HPKE:
the Key Encapsulation Mechanism (KEM), the Key Derivation Function (KDF), and the Authenticated Encryption with Associated Data (AEAD) algorithm.

{{I-D.ietf-hpke-hpke}} defines the HPKE algorithm itself, whereas this document
applies it, unchanged, to COSE. This document is therefore organized
around the COSE message structures rather than around the HPKE specification.
{{hpke-for-cose}} is the core of the specification: after an overview, it
describes the two modes of using HPKE in COSE in the order of increasing
complexity, starting with the single-layer HPKE Integrated Encryption mode ({{one-layer}}),
followed by the two-layer HPKE Key Encryption mode ({{two-layer}}), and then
the representation of the keys used by both modes ({{key-representation}}).
{{ciphersuite}} defines the ciphersuites, i.e., the COSE algorithm identifiers
that select the HPKE algorithms, and their relationship to COSE_Key types.
{{examples}} provides examples for both modes and for the key representation.
Security and IANA considerations follow in {{sec-cons}} and {{IANA}}.
Test vectors are provided in {{test-vectors}}.

# Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP&nbsp;14 {{RFC2119}} {{RFC8174}}
when, and only when, they appear in all capitals, as shown here.

This specification uses the following abbreviations and terms:

- Content-encryption key (CEK), as described in {{Section 2 of RFC9052}}.
- Hybrid Public Key Encryption (HPKE) as defined in {{I-D.ietf-hpke-hpke}}.
- pkR is the public key of the recipient, as defined in {{I-D.ietf-hpke-hpke}}.
- skR is the private key of the recipient, as defined in {{I-D.ietf-hpke-hpke}}.
- Key Encapsulation Mechanism (KEM), see {{I-D.ietf-hpke-hpke}}.
- Key Derivation Function (KDF), see {{I-D.ietf-hpke-hpke}}.
- Authenticated Encryption with Associated Data (AEAD), see {{I-D.ietf-hpke-hpke}}.
- Additional Authenticated Data (AAD), see {{I-D.ietf-hpke-hpke}}.

# HPKE for COSE {#hpke-for-cose}

## Overview

This specification supports two modes of using HPKE in COSE, namely:

 *  HPKE Integrated Encryption mode, where HPKE is used to encrypt
the plaintext. This mode can only be used with a single recipient.
{{one-layer}} provides the details.

 *  HPKE Key Encryption mode, where HPKE is used to encrypt a content
encryption key (CEK), which then encrypts the content.
This mode supports multiple recipients.
{{two-layer}} provides the details.

The two modes correspond to the two ways in which COSE already structures
encrypted messages, and they serve different needs:

 *  The HPKE Integrated Encryption mode uses the COSE_Encrypt0 structure.
The HPKE AEAD protects the content directly, so only a single HPKE operation
is needed and no CEK is conveyed in the message. This yields the most compact
message and the simplest processing, but the message can only be decrypted
by a single recipient.

 *  The HPKE Key Encryption mode uses the COSE_Encrypt structure and is a
Content Key Distribution Method like those in {{Section 8.5 of RFC9052}}.
At the cost of an additional layer and one additional encryption operation,
the content is encrypted only once regardless of the number of recipients,
the content encryption algorithm can be any COSE content encryption algorithm, and COSE-HPKE recipients
can be combined with recipients using other content key distribution methods.

In both modes, COSE-HPKE replaces the COSE_KDF_Context used by the
existing COSE key agreement algorithms with the context binding provided by HPKE.
The rationale for this design, and the security properties that result
from it, are described in {{rationale}} and {{AddInfo}}.

Distinct algorithm identifiers are defined and registered
that are specific to each COSE HPKE mode
so that they are fully specified, as required by {{RFC9864}}.
Algorithm identifiers MUST only be used in the COSE HPKE mode
that is specified for them.

In both cases, the new COSE header parameter "ek" MUST be present.
It contains the encapsulated KEM shared secret.
The value of this parameter MUST be the "enc" value output by the HPKE Seal() Single-Shot operation, as defined in {{Section 6.1 of I-D.ietf-hpke-hpke}}.
The "ek" header parameter MUST be encoded as a CBOR byte string.

HPKE defines several authentication modes, as described in Table 1 of {{I-D.ietf-hpke-hpke}}.
This specification uses both 'mode_base' and 'mode_psk'.
The mode is 'mode_psk' if the "psk_id" header parameter is present; otherwise, the mode defaults to 'mode_base'.
'mode_base' is described in {{Section 5.1.1 of I-D.ietf-hpke-hpke}}, which only enables encryption
to the holder of a given KEM private key. 'mode_psk' is described in {{Section 5.1.2 of I-D.ietf-hpke-hpke}},
which authenticates using a pre-shared key.
The "psk_id" header parameter, when present, MUST be a protected header parameter of the
COSE structure of the corresponding HPKE operation. The PSK value
itself is an external input to HPKE and MUST NOT be encoded in the COSE
structure.

## HPKE Integrated Encryption Mode {#one-layer}

This mode applies if the COSE_Encrypt0 structure uses a COSE-HPKE algorithm
and has no recipient structure(s).

Because COSE-HPKE supports header protection, if the "alg" parameter is present, it MUST be included
in the protected header and MUST be a COSE-HPKE algorithm.

The use of the "kid" header parameter is RECOMMENDED
to explicitly identify the static recipient public key
used by the sender. If the COSE_Encrypt0 structure includes a "kid" parameter, the
recipient MAY use it to select the corresponding private key.

When encrypting, the inputs to the HPKE Seal Single-Shot operation are set as follows:

- kem_id: From the ciphersuite. See {{ciphersuite}}.
- pkR: The recipient public key, converted into an HPKE public key.
- kdf_id: From the ciphersuite. See {{ciphersuite}}.
- psk: If 'mode_psk' has been selected, the externally supplied pre-shared
  key. Otherwise, the empty string.
- psk_id: If 'mode_psk' has been selected, the value of the protected
  "psk_id" header parameter. Otherwise, the empty string.
- info: Defaults to the empty string; externally provided information MAY be used instead.
- aad: MUST contain the byte string for the authenticated data structure according to the steps defined in {{Section 5.3 of RFC9052}}.

For the Integrated Encryption mode the context string will be "Encrypt0".
Externally provided AAD information MAY be provided and MUST be passed into the Enc_structure via the external_aad field.

- aead_id: From the ciphersuite. See {{ciphersuite}}.
- pt: The raw message plaintext.

The outputs are used as follows:

- enc: MUST be placed raw into the "ek" (encapsulated key) parameter in the unprotected bucket.
- ct: MUST be used as layer ciphertext. If not using detached content, this is directly placed as
ciphertext in COSE_Encrypt0 structure. Otherwise, it is transported separately and the ciphertext field is nil.
See {{Section 5 of RFC9052}} for a description of detached payloads.

If 'mode_psk' has been selected, then the "psk_id" parameter MUST be present.
If 'mode_base' has been chosen, then the "psk_id" parameter MUST NOT be present.

When decrypting, the inputs to the HPKE Open operation are set as follows:

- kem_id: From the ciphersuite. See {{ciphersuite}}.
- skR: The recipient private key, converted into an HPKE private key.
- kdf_id: From the ciphersuite. See {{ciphersuite}}.
- aead_id: From the ciphersuite. See {{ciphersuite}}.
- psk: If 'mode_psk' has been selected, the externally supplied pre-shared
  key. Otherwise, the empty string.
- psk_id: If 'mode_psk' has been selected, the value of the protected
  "psk_id" header parameter. Otherwise, the empty string.
- info: Defaults to the empty string; externally provided information MAY be used instead.
- aad: MUST contain the byte string for the authenticated data structure according to the steps defined in {{Section 5.3 of RFC9052}}. For the Integrated Encryption mode the context string will be "Encrypt0". Externally provided AAD information MAY be provided and MUST be passed into the Enc_structure via the external_aad field.
- enc: The contents of the layer "ek" parameter.
- ct: The contents of the layer ciphertext.

The plaintext output is the raw message plaintext.

The COSE_Encrypt0 MAY be tagged or untagged.

An example is shown in {{one-layer-example}}.

## HPKE Key Encryption Mode {#two-layer}

This mode is a Content Key Distribution Method like those specified in {{Section 8.5 of RFC9052}}.
It uses HPKE to protect the CEK.
It is similar to the Key Agreement with Key Wrap method defined in {{Section 8.5.5 of RFC9052}}.
Internally, HPKE performs a key agreement to derive a shared secret and then uses that secret to wrap the CEK.

A COSE_Encrypt structure is used with two logical layers:

- Layer 0 contains the content (plaintext)
encrypted with the CEK. This ciphertext may be detached, and if not detached, then
it is included in the COSE_Encrypt structure.

- Layer 1 contains a COSE_Recipient with the parameters needed for
HPKE to generate a shared secret used to encrypt the CEK. This layer conveys the
encrypted CEK in the COSE_Recipient structure using a COSE-HPKE algorithm.

This two-layer structure is used to encrypt content that can also be shared with
multiple recipients at the expense of a single additional encryption operation.
The content is encrypted once with the CEK, then the CEK is encrypted for each recipient.
Layer 1 may also contain other COSE_Recipients using other content key distribution methods that also encrypt the CEK.

### Recipient_structure

When constructing a COSE_Recipient for COSE-HPKE, the Recipient_structure defined here is used in place of COSE_KDF_Context to aggregate the items that require protection.
COSE-HPKE does not use the COSE_KDF_Context in any way.

The Recipient_structure works akin to Sig_structure and Enc_structure defined in {{RFC9052}}.
It is constructed independently by the sender and the receiver only as an input to the cryptographic algorithms.
It is not actually conveyed in the COSE message.
A CDDL {{RFC8610}} description of the data structure is as follows:

~~~
Recipient_structure = [
    context: "HPKE Recipient",
    next_layer_alg: int/tstr,
    recipient_protected_header: empty_or_serialized_map,
    recipient_extra_info: bstr
]
~~~

"next_layer_alg":
: The algorithm ID of the COSE layer for which the COSE_Recipient is encrypting a key.
It is the algorithm that the key MUST be used with.
This value MUST match the "alg" parameter in the next lower COSE layer.

"recipient_protected_header":
: The protected header parameters from the COSE_Recipient.

"recipient_extra_info":
: Defaults to empty byte string. See {{AddInfo}}.

The Recipient_structure MUST be serialized deterministically in accordance with the Core Deterministic Encoding Requirements defined in {{Section 4.2.1 of RFC8949}}.
This requirement applies only to the Recipient_structure itself &mdash; the array and its four members.
It does not extend into the byte-string wrapped protected headers.


### COSE-HPKE Recipient Construction

This section gives the steps for constructing a COSE_Recipient using HPKE.
Implementations may perform operations in this section in whichever order they choose, so long as the same bytes are produced as a result.

First, the CEK is generated, usually using a high-quality random number generator.

The CEK is used to encrypt the content.
When encrypting the content at layer 0, the instructions in {{Section 5.3
of RFC9052}} MUST be followed, including the calculation of the
authenticated data structure.

Any bulk external data that requires protection should be handled at layer 0 using external_aad.

Next, assemble the protected headers.
Note that they will be wrapped in a byte string.

While the "alg" header parameter is not strictly required in the COSE_Recipient, if present, it must be the ciphersuite used to specify the HPKE algorithms.
See {{ciphersuite}}.
If the "alg" header parameter is present, it MUST be a protected header parameter.

The protected header parameters MAY contain the "kid" header parameter to identify the static recipient
public key that the sender used. Use of the "kid" parameter is RECOMMENDED
to explicitly identify the static recipient public key used by the sender.
Including it in the protected header parameters ensures that it is input into the
key derivation function of HPKE.
If 'mode_psk' has been selected, then the protected header MUST also contain
the "psk_id" parameter. If 'mode_base' has been chosen, then the protected
header MUST NOT contain the "psk_id" parameter.

Next, construct a Recipient_structure as described above.

Next, the HPKE Seal Single-Shot operation is invoked with the following inputs:

- kem_id: From the ciphersuite. See {{ciphersuite}}.
- kdf_id: From the ciphersuite. See {{ciphersuite}}.
- aead_id: From the ciphersuite. See {{ciphersuite}}.
- pkR: The recipient public key, converted into HPKE public key.
- psk: If 'mode_psk' has been selected, the externally supplied pre-shared
  key. Otherwise, the empty string.
- psk_id: If 'mode_psk' has been selected, the value of the protected
  "psk_id" header parameter in the COSE_Recipient. Otherwise, the empty
  string.
- info: Deterministic encoding of the Recipient_structure. See {{AddInfo}}.
- aad: SHOULD be empty. See {{AddInfo}}.
- pt: The CEK.

The outputs go into the COSE_Recipient as follows:

- enc: MUST be placed into the "ek" (encapsulated key) header parameter in the unprotected bucket.
- ct: MUST be placed in the ciphertext field.

A COSE_Recipient structure is computed for each recipient.

Decrypting is largely the inverse of encrypting.

When decrypting, the inputs to the HPKE Open operation are as follows:

- kdf_id: From the "alg" parameter ciphersuite. See {{ciphersuite}}.
- aead_id: From the "alg" parameter ciphersuite. See {{ciphersuite}}.
- kem_id: From the "alg" parameter ciphersuite. See {{ciphersuite}}.
- enc: From the "ek" parameter in the COSE_Recipient headers.
- skR: The recipient private key, converted into an HPKE private key.
- psk: If 'mode_psk' has been selected, the externally supplied pre-shared
  key. Otherwise, the empty string.
- psk_id: If 'mode_psk' has been selected, the value of the protected
  "psk_id" header parameter in the COSE_Recipient. Otherwise, the empty
  string.
- info: Deterministic encoding of the Recipient_structure. See {{AddInfo}}.
- aad: SHOULD be empty. See {{AddInfo}}.
- ct: The contents of the COSE_Recipient ciphertext field.

The plaintext output from the HPKE Open operation is the CEK.

When encrypting the content at layer 0, the instructions in {{Section 5.3
of RFC9052}} MUST be followed, including the calculation of the
authenticated data structure.

An example is shown in {{two-layer-example}}.

### Security Design Rationale {#rationale}

COSE-HPKE does not use COSE_KDF_Context, which is defined in {{Section 5.2 of RFC9053}}, for the following reasons:

- HPKE is a well-analyzed and widely reviewed construction that already incorporates the protections provided by COSE_KDF_Context.
- The HPKE design avoids many of the weaknesses present in earlier key agreement protocols that COSE_KDF_Context was designed to mitigate.
- Use of the COSE_KDF_Context would introduce unnecessary complexity; many of the fields typically go unused.
- It is difficult to know what to put in the COSE_KDF_Context fields.


The algorithm identifier for the bulk content encryption algorithm can be manipulated, since it is neither integrity-protected nor incorporated into the key derivation.
In particular, the layer 0 algorithm identifier is not integrity protected by the COSE_Recipient and is therefore not cryptographically bound to the key agreement algorithm.
This class of attack has been demonstrated against CMS; a corresponding mitigation is described in [I-D.ietf-lamps-cms-cek-hkdf-sha256].

The "next_layer_alg" member of the Recipient_structure mitigates this attack by explicitly binding the bulk content encryption algorithm identifier with the COSE_Recipient.
The "next_layer_alg" member is explicitly defined to identify the algorithm for the immediately following COSE layer.
Such explicit layering semantics were not provided for the AlgorithmID field in COSE_KDF_Context, where the intended interpretation was ambiguous.


### Context Binding and Additional Information {#AddInfo}

All header parameters in the protected bucket of the COSE_Recipient are incorporated into the HPKE Single-Shot Seal/Open info parameter via the Recipient_structure.
As a result, these parameters are both integrity-protected and bound to the HPKE key schedule, since they influence the internal HPKE key setup.

In most cases, additional header parameters carry supplementary data such as a "kid".
If a use case requires binding the encryption context to public information, placing that information in the protected header parameters is a straightforward approach: the value will be transmitted to the recipient and automatically incorporated into the HPKE key schedule.
For example, a new header parameter identifying the application-level protocol that uses COSE-HPKE could be defined.
Its value would be authenticated and would also influence the HPKE key setup.

Because all header parameters are transmitted in the clear, they cannot be used to bind information that must remain secret.
The "recipient_extra_info" field in the Recipient_structure is also included in the HPKE Single-Shot Seal/Open info parameter, but unlike header parameters it is not transmitted.
This makes it suitable for binding context information that is, for example, provided in other layers of the protocol stack or via out-of-band means. It is the responsibility of the specific use case to ensure that both sender and receiver possess this context information.

There are minor size considerations.
HPKE guarantees support for at least 64 bytes in the info parameter, and implementations are expected to support up to 16,384 bytes.
This indirectly imposes a size limit on the COSE_Recipient protected header parameters and the "recipient_extra_info" field.
In practice, this limit is unlikely to pose problems except in highly constrained environments or in use cases with unusually large header parameters.

Protection and binding of auxiliary information can generally be achieved using protected header parameters together with the "recipient_extra_info" field, so use of the Single-Shot Seal/Open aad parameter is rarely necessary.
However, it remains available for special cases and has no practical size limit.


## Key Representation {#key-representation}

The COSE_Key with the existing key types can be used to represent KEM private
or public keys. When using a COSE_Key for COSE-HPKE, the following checks are made:

* If the "kty" field is "AKP", then the public and private keys SHALL be the raw HPKE public and private
keys (respectively) for the KEM used by the algorithm.
* Otherwise, the key MUST be suitable for the KEM used by the algorithm. In case the "kty" parameter
is "EC2" or "OKP", this means the value of "crv" parameter is suitable. The valid combinations of
KEM, "kty" and "crv" for the algorithms defined in this document are shown in {{ciphersuite-kty-crv}}.
* If the "key_ops" field is present, it MUST include only "derive bits" for the private key
and MUST be empty for the public key.

Examples of the COSE_Key for COSE-HPKE are shown in {{key-representation-example}}.

# Ciphersuite Registration {#ciphersuite}

A ciphersuite is a set of cryptographic algorithms selected to achieve a specific security level.
For COSE-HPKE, a single COSE algorithm ID represents a ciphersuite that maps to the following HPKE algorithm identifiers:

- KEM algorithm
- KDF algorithm
- AEAD algorithm

Each COSE algorithm ID registered for COSE-HPKE MUST indicate the three HPKE algorithm IDs mapped by the ciphersuite.

The HPKE mode is determined by the presence or absence of the
"psk_id" parameter and is therefore not explicitly indicated in the
ciphersuite.

For a list of ciphersuite registrations, please see {{IANA}}. The following
table summarizes the relationship between the ciphersuites registered in this
document and the values registered in the HPKE IANA registry {{HPKE-IANA}}.

~~~
+-------------------+-----------------------+-------------------+
| COSE-HPKE         | COSE HPKE Mode        |        HPKE       |
| Ciphersuite Label |                       | KEM  | KDF | AEAD |
+-------------------+-----------------------+------+-----+------+
| HPKE-0            | Integrated Encryption | 0x10 | 0x1 | 0x1  |
| HPKE-1            | Integrated Encryption | 0x11 | 0x2 | 0x2  |
| HPKE-2            | Integrated Encryption | 0x12 | 0x3 | 0x2  |
| HPKE-3            | Integrated Encryption | 0x20 | 0x1 | 0x1  |
| HPKE-4            | Integrated Encryption | 0x20 | 0x1 | 0x3  |
| HPKE-5            | Integrated Encryption | 0x21 | 0x3 | 0x2  |
| HPKE-6            | Integrated Encryption | 0x21 | 0x3 | 0x3  |
| HPKE-7            | Integrated Encryption | 0x10 | 0x1 | 0x2  |
| HPKE-0-KE         | Key Encryption        | 0x10 | 0x1 | 0x1  |
| HPKE-1-KE         | Key Encryption        | 0x11 | 0x2 | 0x2  |
| HPKE-2-KE         | Key Encryption        | 0x12 | 0x3 | 0x2  |
| HPKE-3-KE         | Key Encryption        | 0x20 | 0x1 | 0x1  |
| HPKE-4-KE         | Key Encryption        | 0x20 | 0x1 | 0x3  |
| HPKE-5-KE         | Key Encryption        | 0x21 | 0x3 | 0x2  |
| HPKE-6-KE         | Key Encryption        | 0x21 | 0x3 | 0x3  |
| HPKE-7-KE         | Key Encryption        | 0x10 | 0x1 | 0x2  |
+-------------------+-----------------------+------+-----+------+
~~~

The following list maps the ciphersuite labels to their textual
description.

- HPKE-0: Integrated Encryption with DHKEM(P-256, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-128-GCM AEAD.
- HPKE-1: Integrated Encryption with DHKEM(P-384, HKDF-SHA384) KEM, HKDF-SHA384 KDF, and AES-256-GCM AEAD.
- HPKE-2: Integrated Encryption with DHKEM(P-521, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and AES-256-GCM AEAD.
- HPKE-3: Integrated Encryption with DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-128-GCM AEAD.
- HPKE-4: Integrated Encryption with DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and ChaCha20Poly1305 AEAD.
- HPKE-5: Integrated Encryption with DHKEM(X448, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and AES-256-GCM AEAD.
- HPKE-6: Integrated Encryption with DHKEM(X448, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and ChaCha20Poly1305 AEAD.
- HPKE-7: Integrated Encryption with DHKEM(P-256, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-256-GCM AEAD.
- HPKE-0: Key Encryption with DHKEM(P-256, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-128-GCM AEAD.
- HPKE-1: Key Encryption with DHKEM(P-384, HKDF-SHA384) KEM, HKDF-SHA384 KDF, and AES-256-GCM AEAD.
- HPKE-2: Key Encryption with DHKEM(P-521, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and AES-256-GCM AEAD.
- HPKE-3: Key Encryption with DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-128-GCM AEAD.
- HPKE-4: Key Encryption with DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and ChaCha20Poly1305 AEAD.
- HPKE-5: Key Encryption with DHKEM(X448, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and AES-256-GCM AEAD.
- HPKE-6: Key Encryption with DHKEM(X448, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and ChaCha20Poly1305 AEAD.
- HPKE-7: Key Encryption with DHKEM(P-256, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-256-GCM AEAD.

As the list indicates, the ciphersuite labels have been abbreviated at least
to some extent to strike a balance between readability and length.

The ciphersuite list above is a minimal starting point. Additional
ciphersuites can be registered into the already existing registry.
For example, once post-quantum cryptographic algorithms have been standardized
it might be beneficial to register ciphersuites for use with COSE-HPKE.
Additionally, ciphersuites utilizing the compact encoding of the public keys,
as defined in {{I-D.irtf-cfrg-dnhpke}}, may be standardized for use in
constrained environments.

## COSE_Keys for COSE-HPKE Ciphersuites

The COSE-HPKE algorithm uniquely determines the KEM for which a COSE_Key is used.
The following mapping table shows the valid combinations
of the KEM used, COSE_Key type, and its curve/key subtype.
This holds for COSE algorithms using either of the COSE HPKE modes
(Integrated Encryption and Key Encryption).

~~~
+---------------------+--------------+
| HPKE KEM id         | COSE_Key     |
|                     | kty | crv    |
+---------------------+-----+--------+
| 0x0010, 0x0013      | EC2 | P-256  |
| 0x0011, 0x0014      | EC2 | P-384  |
| 0x0012, 0x0015      | EC2 | P-521  |
| 0x0020              | OKP | X25519 |
| 0x0021              | OKP | X448   |
+---------------------+-----+--------+
~~~
{: #ciphersuite-kty-crv title="COSE_Key Types and Curves for COSE-HPKE Ciphersuites"}

# Examples {#examples}

This section provides a set of examples that show the HPKE Integrated Encryption
Mode and the HPKE Key Encryption Mode, and illustrates the use of key representations
for HPKE KEM.

## COSE HPKE Integrated Encryption Mode {#one-layer-example}

This example assumes that a sender wants to communicate an
encrypted payload to a single recipient, named "bob".

An example of the HPKE Integrated Encryption Mode is
shown in {{hpke-example-one}}. Line breaks and comments have been inserted
for better readability.

This example uses the following:

- Suite: HPKE-0 (P-256 / HKDF-SHA256 / AES-128-GCM)
- Plaintext: "This is the content."
- External AAD: empty
- External Info: empty
- Recipient kid: "bob"

The ciphertext (hex) transmitted to "bob" is:

~~~
d08344a1011823a20443626f622358410457229bdd99407b384a9e59fa15
53224d58b106e9ebebdaa06d2126bd96757674847669966ecb0dcdf21af5
623f19f0b799b0cddf3ee930b739dd474f6282de0158253f3c1595e9d252
e816215a9ce73f47ba4b57acb06ecc39ca5a03a14108bbe7807af5688d61
~~~
{: #hpke-example-ciphertext title="Hex-Encoding of COSE_Encrypt0"}

COSE_Encrypt0 pretty-printed:

~~~
16([
  h'A1011823',
  {
    4: 'bob',
    -4: h'0457229BDD99407B384A9E59FA1553224D58B106E9EBEBDA
    A06D2126BD96757674847669966ECB0DCDF21AF5623F19F0B799B0
    CDDF3EE930B739DD474F6282DE01'
  },
  h'3F3C1595E9D252E816215A9CE73F47BA4B57ACB06ECC39CA5A03A1
  4108BBE7807AF5688D61'
  ])
~~~
{: #hpke-example-one title="COSE_Encrypt0 Example for HPKE"}

The following COSE Key was used in this example:

~~~
{
  1 /kty/: 2,
  2 /kid/: h'626f62',
  3 /alg/: 35 /HPKE-0  (P-256 + HKDF-SHA256 + AES-128-GCM)/,
 -1 /crv/: 1 /P-256/,
 -2 /x/:
  h'02a8e3315f96bc7355dbf85740c6d8e53fb070cd8ba5c419be49a91d789ef55c',
 -3 /y/:
  h'96b6621abf5ca532e042dc5c346c1ef0c9186b83cb122e50a46f1458de023d35',
 -4 /d/:
  h'eca39300147c91a2a65d17e00ea278b57a14178245bf5686d9a404cca1816b8e'
}
~~~
{: #hpke-example-one-key title="COSE Key"}

## COSE HPKE Key Encryption Mode {#two-layer-example}

An example of key encryption using the COSE_Encrypt structure using HPKE is
shown in below. Line breaks and comments have been
inserted for better readability.

This example uses the following input parameters:

- Content encryption algorithm: AES-128-GCM
- plaintext: "This is the content."
- kid:"bob"
- alg: HPKE-0-KE (assumed 46) - Key Encryption, DHKEM(P-256, HKDF-SHA256), KDF: HKDF-SHA256, AEAD: AES-128-GCM
- external aad and info are empty
- IV: 12 bytes, as required for AES-128-GCM by {{Section 4.1 of RFC9053}}

The following COSE Key is used:

~~~
a701020243626f6203182e2001215820d832916778598ea6203af974c97b
45970ac0266fc6a3b7f213ba9f8b591b92972258208d9410599a8e83d00e
b46d67b34d4dac8fbd4b8b1f08864599659cee9ef09184235820b1162c56
8efcba91c8e4e82f66e36b45aa10bc55228cf65ecd3bb29cfb09f989
~~~

As a pretty-printed version:

~~~
{
   1 /kty/: 2,
   2 /kid/: h'626f62' /"bob"/,
   3 /alg/: 46 /HPKE-0-KE/,
  -1 /crv/: 1 /P-256/,
  -2 /x/:
     h'd832916778598ea6203af974c97b45970ac0266fc6a3b7f213ba9
f8b591b9297',
  -3 /y/:
    h'8d9410599a8e83d00eb46d67b34d4dac8fbd4b8b1f08864599659c
ee9ef09184',
  -4 /d/:
    h'b1162c568efcba91c8e4e82f66e36b45aa10bc55228cf65ecd3bb2
9cfb09f989'
}
~~~

As a result, the following COSE_Encrypt payload is
produced:

~~~
d8608443a10101a1054c8623f0b68ccc19415e37b8db5824ded3a96e205d
71b031d01e20186b0c43cde13d701d8f388358bf9504d06238f805c6aa10
818349a201182e0443626f62a123584104d0982992abbc8bafd26840dd46
b2e976e0d36542625041ae315acd52cd704a88e90ec1b1ecf05fcf2355b1
289e87315ddb0cbb85d3c3deb01d6a47e76f3279a8582095e40717a9e15d
fd863ec4725e4dfb4648b5627d125f946e0e2f4c9b9e27989d
~~~

Pretty-printed, this hex-sequence has the following
content:

~~~
96([
  h'A10101',
  {5: h'8623F0B68CCC19415E37B8DB'},
  h'DED3A96E205D71B031D01E20186B0C43CDE13D701D8F388358BF9504
  D06238F805C6AA10',
  [
    [
    h'A201182E0443626F62',
    {-4: h'04D0982992ABBC8BAFD26840DD46B2E976E0D36542625041A
    E315ACD52CD704A88E90EC1B1ECF05FCF2355B1289E87315DDB0CBB8
    5D3C3DEB01D6A47E76F3279A8'},
    h'95E40717A9E15DFD863EC4725E4DFB4648B5627D125F946E0E2F4C
    9B9E27989D']]
  ])
~~~

## Key Representation {#key-representation-example}

Examples of private and public KEM key representation are shown below.

### Public Key for HPKE-0

~~~
{
    / kty = 'EC2' /
    1: 2,
    / kid = '01' /
    2: h'3031',
    / alg = HPKE-0 (Assumed: 35) /
    3: 35,
    / crv = 'P-256' /
    -1: 1,
    / x /
    -2: h'65eda5a12577c2bae829437fe338701a10aaa375
          e1bb5b5de108de439c08551d',
    / y /
    -3: h'1e52ed75701163f7f9e40ddf9f341b3dc9ba860af
          7e0ca7ca7e9eecd0084d19c'
}
~~~
{: #hpke-example-key-1 title="Public Key Representation Example for HPKE-0"}


### Private Key for HPKE-0

~~~
{
    / kty = 'EC2' /
    1: 2,
    / kid = '01' /
    2: h'3031',
    / alg = HPKE-0 (Assumed: 35) /
    3: 35,
    / key_ops = ['derive_bits'] /
    4: [8],
    / crv = 'P-256' /
    -1: 1,
    / x /
    -2: h'bac5b11cad8f99f9c72b05cf4b9e26d244dc189f7
          45228255a219a86d6a09eff',
    / y /
    -3: h'20138bf82dc1b6d562be0fa54ab7804a3a64b6d72
          ccfed6b6fb6ed28bbfc117e',
    / d /
    -4: h'57c92077664146e876760c9520d054aa93c3afb04
          e306705db6090308507b4d3',
}
~~~
{: #hpke-example-key-2 title="Private Key Representation Example for HPKE-0"}


### KEM Public Key for HPKE-4

~~~
{
    / kty = 'OKP' /
    1: 1,
    / kid = '11' /
    2: h'3131',
    / alg = HPKE-4 (Assumed: 42) /
    3: 42,
    / crv = 'X25519' /
    -1: 4,
    / x /
    -2: h'cb7c09ab7b973c77a808ee05b9bbd373b55c06eaa
          9bd4ad2bd4e9931b1c34c22',
}
~~~
{: #hpke-example-key-3 title="Public Key Representation Example for HPKE-4"}

# Security Considerations {#sec-cons}

This specification is based on HPKE and the security considerations of
{{I-D.ietf-hpke-hpke}} are therefore applicable also to this specification.

Both HPKE and HPKE COSE assume that the sender possesses the recipient's
public key. Therefore, some form of public key distribution mechanism is
assumed to exist, but this is outside the scope of this document.

HPKE requires a cryptographically secure source of randomness. In HPKE Key
Encryption mode, the CEK MUST also be generated using a cryptographically secure
random number generator. {{RFC8937}} describes a technique for improving
resilience to weaknesses in random number generation.

HPKE in Base mode does not offer authentication as part of the HPKE KEM. In this
case COSE constructs like COSE_Sign, COSE_Sign1, COSE_Mac, or COSE_Mac0 can be
used to add authentication.

If COSE_Encrypt or COSE_Encrypt0 is used with a detached ciphertext then the
subsequently applied integrity protection via COSE_Sign, COSE_Sign1, COSE_Mac,
or COSE_Mac0 does not cover this detached ciphertext. Implementers MUST ensure
that the detached ciphertext also experiences integrity protection. This is, for
example, the case when an AEAD cipher is used to produce the detached ciphertext
but may not be guaranteed by non-AEAD ciphers.

#  IANA Considerations {#IANA}

This document requests IANA to add new values to the 'COSE Algorithms' and to
the 'COSE Header Parameters' registries.

## Designated Expert Guidance {#designated-expert-guidance}

For ciphersuite submissions to the IANA COSE Algorithms registry, designated
experts must only register combinations of (KEM, KDF, AEAD) triple that
constitute valid combinations for use with HPKE. The KDF used should, if
possible, match one internally used by the KEM. Components should not be mixed
between global and national standards.

## COSE Algorithms Registry

IANA is requested to register the algorithms listed in {{iana-algs}}.
The following values apply to all of these registrations:

-  Capabilities: [kty]
-  Change Controller: IESG
-  Reference:  [[TBD: This RFC]]
-  Recommended: Yes

| Name | Value | Description |
|---|---|---|
| HPKE-0 | TBD1 (Assumed: 35) | COSE HPKE Integrated Encryption using DHKEM(P-256, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-128-GCM AEAD. |
| HPKE-1 | TBD3 (Assumed: 37) | COSE HPKE Integrated Encryption using DHKEM(P-384, HKDF-SHA384) KEM, HKDF-SHA384 KDF, and AES-256-GCM AEAD. |
| HPKE-2 | TBD5 (Assumed: 39) | COSE HPKE Integrated Encryption using DHKEM(P-521, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and AES-256-GCM AEAD. |
| HPKE-3 | TBD7 (Assumed: 41) | COSE HPKE Integrated Encryption using DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-128-GCM AEAD. |
| HPKE-4 | TBD8 (Assumed: 42) | COSE HPKE Integrated Encryption using DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and ChaCha20Poly1305 AEAD. |
| HPKE-5 | TBD9 (Assumed: 43) | COSE HPKE Integrated Encryption using DHKEM(X448, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and AES-256-GCM AEAD. |
| HPKE-6 | TBD10 (Assumed: 44) | COSE HPKE Integrated Encryption using DHKEM(X448, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and ChaCha20Poly1305 AEAD. |
| HPKE-7 | TBD13 (Assumed: 45) | COSE HPKE Integrated Encryption using DHKEM(P-256, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-256-GCM AEAD. |
| HPKE-0-KE | TBD14 (Assumed: 46) | COSE HPKE Key Encryption using DHKEM(P-256, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-128-GCM AEAD. |
| HPKE-1-KE | TBD15 (Assumed: 47) | COSE HPKE Key Encryption using DHKEM(P-384, HKDF-SHA384) KEM, HKDF-SHA384 KDF, and AES-256-GCM AEAD. |
| HPKE-2-KE | TBD16 (Assumed: 48) | COSE HPKE Key Encryption using DHKEM(P-521, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and AES-256-GCM AEAD. |
| HPKE-3-KE | TBD17 (Assumed: 49) | COSE HPKE Key Encryption using DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-128-GCM AEAD. |
| HPKE-4-KE | TBD18 (Assumed: 50) | COSE HPKE Key Encryption using DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and ChaCha20Poly1305 AEAD. |
| HPKE-5-KE | TBD19 (Assumed: 51) | COSE HPKE Key Encryption using DHKEM(X448, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and AES-256-GCM AEAD. |
| HPKE-6-KE | TBD20 (Assumed: 52) | COSE HPKE Key Encryption using DHKEM(X448, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and ChaCha20Poly1305 AEAD. |
| HPKE-7-KE | TBD21 (Assumed: 53) | COSE HPKE Key Encryption using DHKEM(P-256, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-256-GCM AEAD. |
{: #iana-algs title="COSE Algorithms Registrations"}

## COSE Header Parameters

### ek Header Parameter

-  Name: ek
-  Label: TBD11 (Assumed: -4)
-  Value type: bstr
-  Value Registry: N/A
-  Description: HPKE encapsulated key
-  Reference: [[TBD: This RFC]]

### psk_id Header Parameter

-  Name: psk_id
-  Label: TBD12 (Assumed: -5)
-  Value type: bstr
-  Value Registry: N/A
-  Description: A key identifier (kid) for the pre-shared key
as defined in {{Section 5.1.2 of I-D.ietf-hpke-hpke}}
-  Usage: This header parameter MUST be a protected header parameter of
   the COSE_Encrypt0 or COSE_Recipient structure for the HPKE
   operation. It MUST NOT be present as an unprotected header parameter.
-  Reference: [[TBD: This RFC]]

--- back

# Contributors

We would like to thank the following individuals for their contributions
to the design of embedding the HPKE output into the COSE structure
following a long and lively mailing list discussion:

- Richard Barnes
- Ilari Liusvaara

Finally, we would like to thank Russ Housley and Brendan Moran for their
contributions to the draft as co-authors of initial versions.

# Acknowledgements

We would like to thank
Linda Dunbar,
Thomas Fossati,
Chris Inacio,
Mallory Knodel,
John Mattsson,
Ivaylo Petrov,
Mike Prorock,
Michael Richardson,
Göran Selander,
Brian Sipos,
and
Valery Smyslov
for their contributions to the specification.

# Test Vectors {#test-vectors}

The test vectors use the following input:

- Plaintext: "hpke test payload"
- AAD: "external-aad"
- Info: "external-info"
- HPKE AAD: "external-hpke-aad"
- PSK (for the PSK test vectors only):
  h'0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82'
- PSK ID (for the PSK test vectors only):
  h'456e6e796e20447572696e206172616e204d6f726961' (= "Ennyn Durin aran Moria")

AAD is the COSE Enc_structure.external_aad. It is used as AAD for the
COSE AEAD in Encrypt0/Encrypt (Layer 0). HPKE AAD is the HPKE AAD for
CEK wrap/unwrap in Key Encryption (Layer 1). It is only passed to the
HPKE Seal/Open of the CEK.

~~~
{::include-fold testvectors.txt}
~~~
