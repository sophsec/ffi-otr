require 'ffi/otr/types'

require 'ffi'

module FFI
  module OTR
    extend FFI::Library

    ffi_lib_flags :now, :global
    ffi_lib ['otr', 'libotr.so.5']

    # auth.h
    attach_function :otrl_auth_new, [:pointer], :void
    attach_function :otrl_auth_clear, [:pointer], :void
    attach_function :otrl_auth_start_v23, [:pointer], :gcry_error_t
    attach_function :otrl_auth_handle_commit, [:pointer, :string], :gcry_error_t
    attach_function :otrl_auth_handle_key, [:pointer, :pointer, :pointer, :pointer], :gcry_error_t
    attach_function :otrl_auth_handle_revealsig, [:pointer, :string, :pointer, :pointer, :auth_succeeded, :pointer], :gcry_error_t
    attach_function :otrl_auth_handle_signature, [:pointer, :string, :pointer, :auth_succeeded, :pointer], :gcry_error_t
    attach_function :otrl_auth_start_v1, [:pointer, :pointer, :uint, :pointer], :gcry_error_t
    attach_function :otrl_auth_handle_v1_key_exchange, [:pointer, :string, :pointer, :pointer, :pointer, :uint, :auth_succeeded, :pointer], :gcry_error_t

    # b64.h
    attach_function :otrl_base64_encode, [:buffer_out, :buffer_in, :size_t], :size_t
    attach_function :otrl_base64_decode, [:buffer_out, :buffer_in, :size_t], :size_t

    # context.h
    attach_function :otrl_context_find, [:user_state, :string, :string, :string, :int, :pointer, :add_app_data, :pointer], :pointer
    attach_function :otrl_context_find_fingerprint, [:user_state, :pointer, :int, :pointer], :pointer
    attach_function :otrl_context_set_trust, [:pointer, :string], :void
    # attach_function :otrl_context_set_preshared_secret, [:pointer, :buffer_in, :size_t], :void
    attach_function :otrl_context_force_finished, [:pointer], :void
    attach_function :otrl_context_force_plaintext, [:pointer], :void
    attach_function :otrl_context_forget_fingerprint, [:pointer, :int], :void
    attach_function :otrl_context_forget, [:pointer], :void
    attach_function :otrl_context_forget_all, [:pointer], :void

    # dh.h
    attach_function :otrl_dh_init, [], :void
    attach_function :otrl_dh_keypair_init, [:pointer], :void
    attach_function :otrl_dh_keypair_copy, [:pointer, :pointer], :void
    attach_function :otrl_dh_keypair_free, [:pointer], :void
    attach_function :otrl_dh_gen_keypair, [:uint, :pointer], :gcry_error_t
    attach_function :otrl_dh_session, [:pointer, :pointer, :gcry_mpi_t], :gcry_error_t
    attach_function :otrl_dh_compute_v2_auth_keys, [:pointer, :gcry_mpi_t, :buffer_out, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :gcry_error_t
    attach_function :otrl_dh_compute_v1_session_id, [:pointer, :gcry_mpi_t, :buffer_out, :pointer, :pointer], :gcry_error_t
    attach_function :otrl_dh_session_free, [:pointer], :void
    attach_function :otrl_dh_session_blank, [:pointer], :void
    attach_function :otrl_dh_incctr, [:pointer], :void
    attach_function :otrl_dh_cmpctr, [:pointer, :pointer], :int

    # instag.h

    # Forget the given instag.
    #  void otrl_instag_forget(OtrlInsTag* instag);
    attach_function :otrl_instag_forget, [InsTag], :void

    # Forget all instags in a given OtrlUserState.
    #  void otrl_instag_forget_all(OtrlUserState us);
    attach_function :otrl_instag_forget_all, [:user_state], :void

    # Fetch the instance tag from the given OtrlUserState associated with
    # the given account
    #  OtrlInsTag * otrl_instag_find(OtrlUserState us, const char *accountname,
    #    const char *protocol);
    attach_function :otrl_instag_find, [:user_state, :string, :string], InsTag

    # Read our instance tag from a file on disk into the given
    # OtrlUserState.
    #  gcry_error_t otrl_instag_read(OtrlUserState us, const char *filename);
    attach_function :otrl_instag_read, [:user_state, :string], :gcry_error_t

    # Read our instance tag from a file on disk into the given
    # OtrlUserState. The FILE* must be open for reading.
    #  gcry_error_t otrl_instag_read_FILEp(OtrlUserState us, FILE *instf);
    attach_function :otrl_instag_read_FILEp, [:user_state, :pointer], :gcry_error_t

    # Return a new valid instance tag
    #  otrl_instag_t otrl_instag_get_new();
    attach_function :otrl_instag_get_new, [], :instag_t

    # Get a new instance tag for the given account and write to file
    #  gcry_error_t otrl_instag_generate(OtrlUserState us, const char *filename,
    #    const char *accountname, const char *protocol);
    attach_function :otrl_instag_generate, [:user_state, :string, :string, :string],
                    :gcry_error_t

    # Get a new instance tag for the given account and write to file
    # The FILE* must be open for writing.
    #  gcry_error_t otrl_instag_generate_FILEp(OtrlUserState us, FILE *instf,
    #    const char *accountname, const char *protocol);
    attach_function :otrl_instag_generate_FILEp,
                    [:user_state, :pointer, :string, :string], :gcry_error_t

    # Write our instance tags to a file on disk.
    #  gcry_error_t otrl_instag_write(OtrlUserState us, const char *filename);
    attach_function :otrl_instag_write, [:user_state, :string], :gcry_error_t

    # Write our instance tags to a file on disk.
    # The FILE* must be open for writing.
    #  gcry_error_t otrl_instag_write_FILEp(OtrlUserState us, FILE *instf);
    attach_function :otrl_instag_write_FILEp, [:user_state, :pointer], :gcry_error_t

    # mem.h
    attach_function :otrl_mem_init, [], :void

    # message.h
    attach_function :otrl_message_free, [:pointer], :void

    # gcry_error_t otrl_message_sending(OtrlUserState us,
    #   const OtrlMessageAppOps *ops,
    #   void *opdata, const char *accountname, const char *protocol,
    #   const char *recipient, otrl_instag_t instag, const char *original_msg,
    #   OtrlTLV *tlvs, char **messagep, OtrlFragmentPolicy fragPolicy,
    #   ConnContext **contextp,
    #   void (*add_appdata)(void *data, ConnContext *context),
    #   void *data);
    attach_function :otrl_message_sending, [
                      :user_state, # us
                      OtrlMessageAppOps, # ops
                      :opdata, # opdata
                      :string, # accountname
                      :string, # protocol
                      :string, # recipient
                      :instag_t, # instag
                      :string, # original_msg
                      :pointer, # tlvs
                      :pointer, # messagep
                      :pointer, # fragPolicy
                      :context, # contextp
                      :add_app_data, # add_apdata
                      :pointer # data
                    ], :gcry_error_t

    # int otrl_message_receiving(OtrlUserState us, const OtrlMessageAppOps *ops,
    #   void *opdata, const char *accountname, const char *protocol,
    #   const char *sender, const char *message, char **newmessagep,
    #   OtrlTLV **tlvsp, ConnContext **contextp,
    #   void (*add_appdata)(void *data, ConnContext *context),
    #   void *data);
    attach_function :otrl_message_receiving, [
                      :user_state, # us
                      OtrlMessageAppOps, # ops
                      :opdata, # opdata
                      :string, # accountname
                      :string, # protocol
                      :string, # sender
                      :string, # message
                      :pointer, # newmessagep
                      :pointer, # tlvs
                      :context, # contextp
                      :add_app_data, # add_appdata
                      :pointer # data
                    ], :int

    attach_function :otrl_message_disconnect, [:user_state, :pointer, :pointer, :string, :string, :string], :void
    attach_function :otrl_message_initiate_smp, [:user_state, :pointer, :pointer, :pointer, :buffer_in, :size_t], :void
    attach_function :otrl_message_initiate_smp_q, [:user_state, :pointer, :pointer, :pointer, :string, :buffer_in, :size_t], :void
    attach_function :otrl_message_respond_smp, [:user_state, :pointer, :pointer, :pointer, :buffer_in, :size_t], :void
    attach_function :otrl_message_abort_smp, [:user_state, :pointer, :pointer, :pointer], :void

    # privkey.h
    attach_function :otrl_privkey_hash_to_human, [:buffer_out, :buffer_in], :void
    attach_function :otrl_privkey_fingerprint, [:user_state, :buffer_out, :string, :string], :pointer
    attach_function :otrl_privkey_fingerprint_raw, [:user_state, :buffer_out, :string, :string], :buffer_out
    attach_function :otrl_privkey_read, [:user_state, :string], :gcry_error_t
    attach_function :otrl_privkey_read_FILEp, [:user_state, :pointer], :gcry_error_t
    attach_function :otrl_privkey_generate, [:user_state, :string, :string, :string], :gcry_error_t
    attach_function :otrl_privkey_generate_FILEp, [:user_state, :pointer, :string, :string], :gcry_error_t
    attach_function :otrl_privkey_read_fingerprints, [:user_state, :string, :add_app_data, :pointer], :gcry_error_t
    attach_function :otrl_privkey_read_fingerprints_FILEp, [:user_state, :pointer, :add_app_data, :pointer], :gcry_error_t
    attach_function :otrl_privkey_write_fingerprints, [:user_state, :string], :gcry_error_t
    attach_function :otrl_privkey_write_fingerprints_FILEp, [:user_state, :pointer], :gcry_error_t
    attach_function :otrl_privkey_find, [:user_state, :string, :string], :pointer
    attach_function :otrl_privkey_forget, [:pointer], :void
    attach_function :otrl_privkey_forget_all, [:user_state], :void
    attach_function :otrl_privkey_sign, [:pointer, :pointer, :pointer, :buffer_in, :size_t], :gcry_error_t
    attach_function :otrl_privkey_verify, [:buffer_in, :size_t, :ushort, :gcry_sexp_t, :buffer_in, :size_t], :gcry_error_t

    # proto.h
    attach_function :otrl_init, [:uint, :uint, :uint], :void
    attach_function :otrl_version, [], :string
    attach_function :otrl_proto_default_query_msg, [:string, :otrl_policy], :pointer
    attach_function :otrl_proto_query_bestversion, [:string, :otrl_policy], :uint
    attach_function :otrl_proto_whitespace_bestversion, [:string, :pointer, :pointer, :otrl_policy], :uint
    attach_function :otrl_proto_message_type, [:string], :otrl_message_type
    attach_function :otrl_proto_create_data, [:pointer, :pointer, :string, :pointer, :uchar], :gcry_error_t
    attach_function :otrl_proto_data_read_flags, [:string, :pointer], :gcry_error_t
    attach_function :otrl_proto_accept_data, [:pointer, :pointer, :pointer, :string, :pointer], :gcry_error_t
    attach_function :otrl_proto_fragment_accumulate, [:pointer, :pointer, :string], :otrl_fragment_result
    attach_function :otrl_proto_fragment_create, [:int, :int, :pointer, :string], :gcry_error_t
    attach_function :otrl_proto_fragment_free, [:pointer, :ushort], :void

    # sm.h
    attach_function :otrl_sm_init, [], :void
    attach_function :otrl_sm_state_init, [:pointer], :void
    attach_function :otrl_sm_state_free, [:pointer], :void
    attach_function :otrl_sm_step1, [:pointer, :pointer, :int, :pointer, :pointer], :gcry_error_t
    attach_function :otrl_sm_step2a, [:pointer, :pointer, :int, :int], :gcry_error_t
    attach_function :otrl_sm_step2b, [:pointer, :pointer, :int, :pointer, :pointer], :gcry_error_t
    attach_function :otrl_sm_step3, [:pointer, :pointer, :int, :pointer, :pointer], :gcry_error_t
    attach_function :otrl_sm_step4, [:pointer, :pointer, :int, :pointer, :pointer], :gcry_error_t
    attach_function :otrl_sm_step5, [:pointer, :pointer, :int], :gcry_error_t

    # tlv.h
    attach_function :otrl_tlv_new, [:ushort, :ushort, :buffer_in], :pointer
    attach_function :otrl_tlv_parse, [:buffer_in, :size_t], :pointer
    attach_function :otrl_tlv_free, [:pointer], :void
    attach_function :otrl_tlv_seriallen, [:pointer], :size_t
    attach_function :otrl_tlv_serialize, [:buffer_out, :pointer], :void
    attach_function :otrl_tlv_find, [:pointer, :ushort], :pointer

    # userstate.h
    attach_function :otrl_userstate_create, [], :user_state
    attach_function :otrl_userstate_free, [:user_state], :void


    # proto.h

    POLICY_ALLOW_V1 = 0x01
    POLICY_ALLOW_V2 = 0x02
    POLICY_ALLOW_V3 = 0x04
    POLICY_REQUIRE_ENCRYPTION = 0x08
    POLICY_SEND_WHITESPACE_TAG = 0x10
    POLICY_WHITESPACE_START_AKE = 0x20
    POLICY_ERROR_START_AKE = 0x40

    POLICY_VERSION_MASK = POLICY_ALLOW_V1 | POLICY_ALLOW_V2 | POLICY_ALLOW_V3

    POLICY_NEVER = 0x00
    POLICY_OPPORTUNISTIC = POLICY_ALLOW_V2 | POLICY_ALLOW_V3 |
      POLICY_SEND_WHITESPACE_TAG | POLICY_WHITESPACE_START_AKE | POLICY_ERROR_START_AKE
    POLICY_MANUAL = POLICY_ALLOW_V2 | POLICY_ALLOW_V3
    POLICY_ALWAYS = POLICY_ALLOW_V2 | POLICY_ALLOW_V3 |
      POLICY_REQUIRE_ENCRYPTION | POLICY_WHITESPACE_START_AKE | POLICY_ERROR_START_AKE
    POLICY_DEFAULT = POLICY_OPPORTUNISTIC

    #
    # The version of the OTR library.
    #
    # @return [String]
    #   The version string of the library.
    #
    def self.version
      otrl_version
    end
  end
end
