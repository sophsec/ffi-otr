require 'ffi/otr/types'

require 'ffi'

module FFI
  module OTR
    extend FFI::Library

    ffi_lib 'otr'

    # auth.h
    attach_function :otrl_auth_new, [:pointer], :void
    attach_function :otrl_auth_clear, [:pointer], :void
    attach_function :otrl_auth_start_v2, [:pointer], :gcry_error_t
    attach_function :otrl_auth_handle_commit, [:pointer, :pointer], :gcry_error_t
    attach_function :otrl_auth_handle_key, [:pointer, :pointer, :pointer, :pointer], :gcry_error_t
    attach_function :otrl_auth_handle_revealsig, [:pointer, :pointer, :pointer, :pointer, :auth_succeeded, :pointer], :gcry_error_t
    attach_function :otrl_auth_handle_signature, [:pointer, :pointer, :pointer, :auth_succeeded, :pointer], :gcry_error_t
    attach_function :otrl_auth_start_v1, [:pointer, :pointer, :uint, :pointer], :gcry_error_t
    attach_function :otrl_auth_handle_v1_key_exchange, [:pointer, :pointer, :pointer, :pointer, :pointer, :uint, :auth_succeeded, :pointer], :gcry_error_t

    # b64.h
    attach_function :otrl_base64_encode, [:pointer, :pointer, :size_t], :size_t
    attach_function :otrl_base64_decode, [:pointer, :pointer, :size_t], :size_t

    # context.h
    attach_function :otrl_context_find, [:otrl_user_state, :pointer, :pointer, :pointer, :int, :pointer, :add_app_data, :pointer], :pointer
    attach_function :otrl_context_find_fingerprint, [:otrl_user_state, :pointer, :int, :pointer], :pointer
    attach_function :otrl_context_set_trust, [:pointer, :pointer], :void
    attach_function :otrl_context_set_preshared_secret, [:pointer, :pointer, :size_t], :void
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
    attach_function :otrl_dh_compute_v2_auth_keys, [:pointer, :gcry_mpi_t, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :gcry_error_t
    attach_function :otrl_dh_compute_v1_session_id, [:pointer, :gcry_mpi_t, :pointer, :pointer, :pointer], :gcry_error_t
    attach_function :otrl_dh_session_free, [:pointer], :void
    attach_function :otrl_dh_session_blank, [:pointer], :void
    attach_function :otrl_dh_incctr, [:pointer], :void
    attach_function :otrl_dh_cmpctr, [:pointer, :pointer], :int

    # mem.h
    attach_function :otrl_mem_init, [], :void

    # message.h
    attach_function :otrl_message_free, [:pointer], :void
    attach_function :otrl_message_sending, [:otrl_user_state, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :add_app_data, :pointer], :gcry_error_t
    attach_function :otrl_message_receiving, [:otrl_user_state, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :add_app_data, :pointer], :int
    attach_function :otrl_message_fragment_and_send, [:pointer, :pointer, :pointer, :pointer, :otrl_fragment_policy, :pointer], :gcry_error_t
    attach_function :otrl_message_disconnect, [:otrl_user_state, :pointer, :pointer, :pointer, :pointer, :pointer], :void
    attach_function :otrl_message_initiate_smp, [:otrl_user_state, :pointer, :pointer, :pointer, :pointer, :size_t], :void
    attach_function :otrl_message_initiate_smp_q, [:otrl_user_state, :pointer, :pointer, :pointer, :pointer, :pointer, :size_t], :void
    attach_function :otrl_message_respond_smp, [:otrl_user_state, :pointer, :pointer, :pointer, :pointer, :size_t], :void
    attach_function :otrl_message_abort_smp, [:otrl_user_state, :pointer, :pointer, :pointer], :void

    # privkey.h
    attach_function :otrl_privkey_hash_to_human, [:pointer, :pointer], :void
    attach_function :otrl_privkey_fingerprint, [:otrl_user_state, :pointer, :pointer, :pointer], :pointer
    attach_function :otrl_privkey_fingerprint_raw, [:otrl_user_state, :pointer, :pointer, :pointer], :pointer
    attach_function :otrl_privkey_read, [:otrl_user_state, :pointer], :gcry_error_t
    attach_function :otrl_privkey_read_FILEp, [:otrl_user_state, :pointer], :gcry_error_t
    attach_function :otrl_privkey_generate, [:otrl_user_state, :pointer, :pointer, :pointer], :gcry_error_t
    attach_function :otrl_privkey_generate_FILEp, [:otrl_user_state, :pointer, :pointer, :pointer], :gcry_error_t
    attach_function :otrl_privkey_read_fingerprints, [:otrl_user_state, :pointer, :add_app_data, :pointer], :gcry_error_t
    attach_function :otrl_privkey_read_fingerprints_FILEp, [:otrl_user_state, :pointer, :add_app_data, :pointer], :gcry_error_t
    attach_function :otrl_privkey_write_fingerprints, [:otrl_user_state, :pointer], :gcry_error_t
    attach_function :otrl_privkey_write_fingerprints_FILEp, [:otrl_user_state, :pointer], :gcry_error_t
    attach_function :otrl_privkey_find, [:otrl_user_state, :pointer, :pointer], :pointer
    attach_function :otrl_privkey_forget, [:pointer], :void
    attach_function :otrl_privkey_forget_all, [:otrl_user_state], :void
    attach_function :otrl_privkey_sign, [:pointer, :pointer, :pointer, :pointer, :size_t], :gcry_error_t
    attach_function :otrl_privkey_verify, [:pointer, :size_t, :ushort, :gcry_sexp_t, :pointer, :size_t], :gcry_error_t

    # proto.h
    attach_function :otrl_init, [:uint, :uint, :uint], :void
    attach_function :otrl_version, [], :string
    attach_function :otrl_proto_default_query_msg, [:pointer, :otrl_policy], :pointer
    attach_function :otrl_proto_query_bestversion, [:pointer, :otrl_policy], :uint
    attach_function :otrl_proto_whitespace_bestversion, [:pointer, :pointer, :pointer, :otrl_policy], :uint
    attach_function :otrl_proto_message_type, [:pointer], :otrl_message_type
    attach_function :otrl_proto_create_data, [:pointer, :pointer, :pointer, :pointer, :uchar], :gcry_error_t
    attach_function :otrl_proto_data_read_flags, [:pointer, :pointer], :gcry_error_t
    attach_function :otrl_proto_accept_data, [:pointer, :pointer, :pointer, :pointer, :pointer], :gcry_error_t
    attach_function :otrl_proto_fragment_accumulate, [:pointer, :pointer, :pointer], :otrl_fragment_result
    attach_function :otrl_proto_fragment_create, [:int, :int, :pointer, :pointer], :gcry_error_t
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
    attach_function :otrl_tlv_new, [:ushort, :ushort, :pointer], :pointer
    attach_function :otrl_tlv_parse, [:pointer, :size_t], :pointer
    attach_function :otrl_tlv_free, [:pointer], :void
    attach_function :otrl_tlv_seriallen, [:pointer], :size_t
    attach_function :otrl_tlv_serialize, [:pointer, :pointer], :void
    attach_function :otrl_tlv_find, [:pointer, :ushort], :pointer

    # userstate.h
    attach_function :otrl_userstate_create, [], :otrl_user_state
    attach_function :otrl_userstate_free, [:otrl_user_state], :void

    #
    # The version of the OTR library.
    #
    # @return [String]
    #   The version string of the library.
    #
    def OTR.version
      OTR.otrl_version
    end
  end
end
