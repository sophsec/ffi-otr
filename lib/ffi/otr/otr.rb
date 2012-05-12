require 'ffi/otr/types'

require 'ffi'

module FFI
  module OTR
    extend FFI::Library

    ffi_lib_flags :now, :global
    ffi_lib ['otr', 'libotr.so.2']

    # auth.h
    attach_function :otrl_auth_new, [:pointer], :void
    attach_function :otrl_auth_clear, [:pointer], :void
    attach_function :otrl_auth_start_v2, [:pointer], :gcry_error_t
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
    attach_function :otrl_context_find, [:otrl_user_state, :string, :string, :string, :int, :pointer, :add_app_data, :pointer], :pointer
    attach_function :otrl_context_find_fingerprint, [:otrl_user_state, :pointer, :int, :pointer], :pointer
    attach_function :otrl_context_set_trust, [:pointer, :string], :void
    attach_function :otrl_context_set_preshared_secret, [:pointer, :buffer_in, :size_t], :void
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

    # mem.h
    attach_function :otrl_mem_init, [], :void

    # message.h
    attach_function :otrl_message_free, [:pointer], :void
    attach_function :otrl_message_sending, [:otrl_user_state, :pointer, :pointer, :string, :string, :string, :string, :pointer, :pointer, :add_app_data, :pointer], :gcry_error_t
    attach_function :otrl_message_receiving, [:otrl_user_state, :pointer, :pointer, :string, :string, :string, :string, :pointer, :pointer, :add_app_data, :pointer], :int
    attach_function :otrl_message_fragment_and_send, [:pointer, :pointer, :pointer, :string, :otrl_fragment_policy, :pointer], :gcry_error_t
    attach_function :otrl_message_disconnect, [:otrl_user_state, :pointer, :pointer, :string, :string, :string], :void
    attach_function :otrl_message_initiate_smp, [:otrl_user_state, :pointer, :pointer, :pointer, :buffer_in, :size_t], :void
    attach_function :otrl_message_initiate_smp_q, [:otrl_user_state, :pointer, :pointer, :pointer, :string, :buffer_in, :size_t], :void
    attach_function :otrl_message_respond_smp, [:otrl_user_state, :pointer, :pointer, :pointer, :buffer_in, :size_t], :void
    attach_function :otrl_message_abort_smp, [:otrl_user_state, :pointer, :pointer, :pointer], :void

    # privkey.h
    attach_function :otrl_privkey_hash_to_human, [:buffer_out, :buffer_in], :void
    attach_function :otrl_privkey_fingerprint, [:otrl_user_state, :buffer_out, :string, :string], :buffer_out
    attach_function :otrl_privkey_fingerprint_raw, [:otrl_user_state, :buffer_out, :string, :string], :buffer_out
    attach_function :otrl_privkey_read, [:otrl_user_state, :string], :gcry_error_t
    attach_function :otrl_privkey_read_FILEp, [:otrl_user_state, :pointer], :gcry_error_t
    attach_function :otrl_privkey_generate, [:otrl_user_state, :string, :string, :string], :gcry_error_t
    attach_function :otrl_privkey_generate_FILEp, [:otrl_user_state, :pointer, :string, :string], :gcry_error_t
    attach_function :otrl_privkey_read_fingerprints, [:otrl_user_state, :string, :add_app_data, :pointer], :gcry_error_t
    attach_function :otrl_privkey_read_fingerprints_FILEp, [:otrl_user_state, :pointer, :add_app_data, :pointer], :gcry_error_t
    attach_function :otrl_privkey_write_fingerprints, [:otrl_user_state, :string], :gcry_error_t
    attach_function :otrl_privkey_write_fingerprints_FILEp, [:otrl_user_state, :pointer], :gcry_error_t
    attach_function :otrl_privkey_find, [:otrl_user_state, :string, :string], :pointer
    attach_function :otrl_privkey_forget, [:pointer], :void
    attach_function :otrl_privkey_forget_all, [:otrl_user_state], :void
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
    attach_function :otrl_userstate_create, [], :otrl_user_state
    attach_function :otrl_userstate_free, [:otrl_user_state], :void

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
