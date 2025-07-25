# Copyright 2025 Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: agntcy/identity/core/v1alpha1/vc.proto
# Protobuf Python Version: 4.25.1
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from agntcy.identity.core.v1alpha1 import errors_pb2 as agntcy_dot_identity_dot_core_dot_v1alpha1_dot_errors__pb2
from google.protobuf import struct_pb2 as google_dot_protobuf_dot_struct__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n&agntcy/identity/core/v1alpha1/vc.proto\x12\x1d\x61gntcy.identity.core.v1alpha1\x1a*agntcy/identity/core/v1alpha1/errors.proto\x1a\x1cgoogle/protobuf/struct.proto\"N\n\x0b\x42\x61\x64geClaims\x12\x13\n\x02id\x18\x01 \x01(\tH\x00R\x02id\x88\x01\x01\x12\x19\n\x05\x62\x61\x64ge\x18\x02 \x01(\tH\x01R\x05\x62\x61\x64ge\x88\x01\x01\x42\x05\n\x03_idB\x08\n\x06_badge\"\xc6\x01\n\x11\x43redentialContent\x12\\\n\x0c\x63ontent_type\x18\x01 \x01(\x0e\x32\x34.agntcy.identity.core.v1alpha1.CredentialContentTypeH\x00R\x0b\x63ontentType\x88\x01\x01\x12\x36\n\x07\x63ontent\x18\x02 \x01(\x0b\x32\x17.google.protobuf.StructH\x01R\x07\x63ontent\x88\x01\x01\x42\x0f\n\r_content_typeB\n\n\x08_content\"P\n\x10\x43redentialSchema\x12\x17\n\x04type\x18\x01 \x01(\tH\x00R\x04type\x88\x01\x01\x12\x13\n\x02id\x18\x02 \x01(\tH\x01R\x02id\x88\x01\x01\x42\x07\n\x05_typeB\x05\n\x03_id\"\x8b\x02\n\x10\x43redentialStatus\x12\x13\n\x02id\x18\x01 \x01(\tH\x00R\x02id\x88\x01\x01\x12\x17\n\x04type\x18\x02 \x01(\tH\x01R\x04type\x88\x01\x01\x12G\n\ncreated_at\x18\x03 \x01(\x0b\x32#.agntcy.identity.core.v1alpha1.TimeH\x02R\tcreatedAt\x88\x01\x01\x12U\n\x07purpose\x18\x04 \x01(\x0e\x32\x36.agntcy.identity.core.v1alpha1.CredentialStatusPurposeH\x03R\x07purpose\x88\x01\x01\x42\x05\n\x03_idB\x07\n\x05_typeB\r\n\x0b_created_atB\n\n\x08_purpose\"\xad\x01\n\x13\x45nvelopedCredential\x12_\n\renvelope_type\x18\x01 \x01(\x0e\x32\x35.agntcy.identity.core.v1alpha1.CredentialEnvelopeTypeH\x00R\x0c\x65nvelopeType\x88\x01\x01\x12\x19\n\x05value\x18\x02 \x01(\tH\x01R\x05value\x88\x01\x01\x42\x10\n\x0e_envelope_typeB\x08\n\x06_value\"\x9b\x01\n\x05Proof\x12\x17\n\x04type\x18\x01 \x01(\tH\x00R\x04type\x88\x01\x01\x12(\n\rproof_purpose\x18\x02 \x01(\tH\x01R\x0cproofPurpose\x88\x01\x01\x12$\n\x0bproof_value\x18\x03 \x01(\tH\x02R\nproofValue\x88\x01\x01\x42\x07\n\x05_typeB\x10\n\x0e_proof_purposeB\x0e\n\x0c_proof_value\"\xd1\x04\n\x14VerifiableCredential\x12\x18\n\x07\x63ontext\x18\x01 \x03(\tR\x07\x63ontext\x12\x12\n\x04type\x18\x02 \x03(\tR\x04type\x12\x1b\n\x06issuer\x18\x03 \x01(\tH\x00R\x06issuer\x88\x01\x01\x12\x36\n\x07\x63ontent\x18\x04 \x01(\x0b\x32\x17.google.protobuf.StructH\x01R\x07\x63ontent\x88\x01\x01\x12\x13\n\x02id\x18\x05 \x01(\tH\x02R\x02id\x88\x01\x01\x12(\n\rissuance_date\x18\x06 \x01(\tH\x03R\x0cissuanceDate\x88\x01\x01\x12,\n\x0f\x65xpiration_date\x18\x07 \x01(\tH\x04R\x0e\x65xpirationDate\x88\x01\x01\x12\\\n\x11\x63redential_schema\x18\x08 \x03(\x0b\x32/.agntcy.identity.core.v1alpha1.CredentialSchemaR\x10\x63redentialSchema\x12\\\n\x11\x63redential_status\x18\t \x03(\x0b\x32/.agntcy.identity.core.v1alpha1.CredentialStatusR\x10\x63redentialStatus\x12?\n\x05proof\x18\n \x01(\x0b\x32$.agntcy.identity.core.v1alpha1.ProofH\x05R\x05proof\x88\x01\x01\x42\t\n\x07_issuerB\n\n\x08_contentB\x05\n\x03_idB\x10\n\x0e_issuance_dateB\x12\n\x10_expiration_dateB\x08\n\x06_proof\"\xfb\x01\n\x16VerifiablePresentation\x12\x18\n\x07\x63ontext\x18\x01 \x03(\tR\x07\x63ontext\x12\x12\n\x04type\x18\x02 \x03(\tR\x04type\x12h\n\x15verifiable_credential\x18\x03 \x03(\x0b\x32\x33.agntcy.identity.core.v1alpha1.VerifiableCredentialR\x14verifiableCredential\x12?\n\x05proof\x18\x04 \x01(\x0b\x32$.agntcy.identity.core.v1alpha1.ProofH\x00R\x05proof\x88\x01\x01\x42\x08\n\x06_proof\"\xfc\x03\n\x12VerificationResult\x12\x1b\n\x06status\x18\x01 \x01(\x08H\x00R\x06status\x88\x01\x01\x12T\n\x08\x64ocument\x18\x02 \x01(\x0b\x32\x33.agntcy.identity.core.v1alpha1.VerifiableCredentialH\x01R\x08\x64ocument\x88\x01\x01\x12\"\n\nmedia_type\x18\x03 \x01(\tH\x02R\tmediaType\x88\x01\x01\x12#\n\ncontroller\x18\x04 \x01(\tH\x03R\ncontroller\x88\x01\x01\x12I\n\x1e\x63ontrolled_identifier_document\x18\x05 \x01(\tH\x04R\x1c\x63ontrolledIdentifierDocument\x88\x01\x01\x12\x44\n\x08warnings\x18\x06 \x03(\x0b\x32(.agntcy.identity.core.v1alpha1.ErrorInfoR\x08warnings\x12@\n\x06\x65rrors\x18\x07 \x03(\x0b\x32(.agntcy.identity.core.v1alpha1.ErrorInfoR\x06\x65rrorsB\t\n\x07_statusB\x0b\n\t_documentB\r\n\x0b_media_typeB\r\n\x0b_controllerB!\n\x1f_controlled_identifier_document\"\x06\n\x04Time*\x90\x01\n\x15\x43redentialContentType\x12\'\n#CREDENTIAL_CONTENT_TYPE_UNSPECIFIED\x10\x00\x12\'\n#CREDENTIAL_CONTENT_TYPE_AGENT_BADGE\x10\x01\x12%\n!CREDENTIAL_CONTENT_TYPE_MCP_BADGE\x10\x02*\x92\x01\n\x16\x43redentialEnvelopeType\x12(\n$CREDENTIAL_ENVELOPE_TYPE_UNSPECIFIED\x10\x00\x12+\n\'CREDENTIAL_ENVELOPE_TYPE_EMBEDDED_PROOF\x10\x01\x12!\n\x1d\x43REDENTIAL_ENVELOPE_TYPE_JOSE\x10\x02*n\n\x17\x43redentialStatusPurpose\x12)\n%CREDENTIAL_STATUS_PURPOSE_UNSPECIFIED\x10\x00\x12(\n$CREDENTIAL_STATUS_PURPOSE_REVOCATION\x10\x01\x42\x9d\x02\n!com.agntcy.identity.core.v1alpha1B\x07VcProtoP\x01ZXgithub.com/agntcy/identity/api/server/agntcy/identity/core/v1alpha1;identity_core_sdk_go\xa2\x02\x03\x41IC\xaa\x02\x1d\x41gntcy.Identity.Core.V1alpha1\xca\x02\x1d\x41gntcy\\Identity\\Core\\V1alpha1\xe2\x02)Agntcy\\Identity\\Core\\V1alpha1\\GPBMetadata\xea\x02 Agntcy::Identity::Core::V1alpha1b\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'agntcy.identity.core.v1alpha1.vc_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  _globals['DESCRIPTOR']._options = None
  _globals['DESCRIPTOR']._serialized_options = b'\n!com.agntcy.identity.core.v1alpha1B\007VcProtoP\001ZXgithub.com/agntcy/identity/api/server/agntcy/identity/core/v1alpha1;identity_core_sdk_go\242\002\003AIC\252\002\035Agntcy.Identity.Core.V1alpha1\312\002\035Agntcy\\Identity\\Core\\V1alpha1\342\002)Agntcy\\Identity\\Core\\V1alpha1\\GPBMetadata\352\002 Agntcy::Identity::Core::V1alpha1'
  _globals['_CREDENTIALCONTENTTYPE']._serialized_start=2484
  _globals['_CREDENTIALCONTENTTYPE']._serialized_end=2628
  _globals['_CREDENTIALENVELOPETYPE']._serialized_start=2631
  _globals['_CREDENTIALENVELOPETYPE']._serialized_end=2777
  _globals['_CREDENTIALSTATUSPURPOSE']._serialized_start=2779
  _globals['_CREDENTIALSTATUSPURPOSE']._serialized_end=2889
  _globals['_BADGECLAIMS']._serialized_start=147
  _globals['_BADGECLAIMS']._serialized_end=225
  _globals['_CREDENTIALCONTENT']._serialized_start=228
  _globals['_CREDENTIALCONTENT']._serialized_end=426
  _globals['_CREDENTIALSCHEMA']._serialized_start=428
  _globals['_CREDENTIALSCHEMA']._serialized_end=508
  _globals['_CREDENTIALSTATUS']._serialized_start=511
  _globals['_CREDENTIALSTATUS']._serialized_end=778
  _globals['_ENVELOPEDCREDENTIAL']._serialized_start=781
  _globals['_ENVELOPEDCREDENTIAL']._serialized_end=954
  _globals['_PROOF']._serialized_start=957
  _globals['_PROOF']._serialized_end=1112
  _globals['_VERIFIABLECREDENTIAL']._serialized_start=1115
  _globals['_VERIFIABLECREDENTIAL']._serialized_end=1708
  _globals['_VERIFIABLEPRESENTATION']._serialized_start=1711
  _globals['_VERIFIABLEPRESENTATION']._serialized_end=1962
  _globals['_VERIFICATIONRESULT']._serialized_start=1965
  _globals['_VERIFICATIONRESULT']._serialized_end=2473
  _globals['_TIME']._serialized_start=2475
  _globals['_TIME']._serialized_end=2481
# @@protoc_insertion_point(module_scope)
