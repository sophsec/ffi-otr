require 'ffi'

module FFI
  module OTR
    extend FFI::Library

    typedef :uint,        :gpg_error_t
    typedef :gpg_error_t, :gcry_error_t
    typedef :pointer,     :gcry_mpi_t
    typedef :pointer,     :gcry_md_hd_t
    typedef :pointer,     :gcry_cipher_hd_t
    typedef :pointer,     :gcry_sexp_t

    # auth.h
    enum :otrl_auth_state, [
      :none,
      :awaiting_dhkey,
      :awaiting_revealsig,
      :awaiting_sig,
      :v1_setup
    ]

    callback :auth_succeeded, [:pointer, :pointer], :gcry_error_t

    # context.h
    enum :otrl_message_state, [
      :plaintext,
      :encrypted,
      :finished
    ]

    callback :add_app_data, [:pointer, :pointer], :void

    # dh.h
    enum :otrl_session_id_half, [
      :first_half_bold,
      :second_half_bold
    ]

    # message.h
    enum :otrl_notify_level, [
      :error,
      :warning,
      :info
    ]

    callback :policy, [:pointer, :pointer], :uint
    callback :create_privkey, [:pointer, :string, :string], :void
    callback :is_logged_in, [:pointer, :string, :string, :string], :void
    callback :inject_message, [:pointer, :string, :string, :string, :string], :void
    callback :notify, [:pointer, :pointer, :string, :string, :string, :string, :string, :string], :void
    callback :display_otr_message, [:pointer, :string, :string, :string, :string], :void
    callback :update_context_list, [:pointer], :void
    callback :protocol_name, [:pointer, :string], :void
    callback :protocol_name_free, [:pointer, :string], :void
    callback :new_fingerprint, [:pointer, :pointer, :string, :string, :string, :string], :void
    callback :write_fingerprints, [:pointer], :void
    callback :gone_secure, [:pointer, :pointer, :int], :void
    callback :gone_insecure, [:pointer, :pointer], :void
    callback :still_secure, [:pointer, :pointer, :int, :int], :void
    callback :log_message, [:pointer, :string], :void
    callback :max_message_size, [:pointer, :pointer], :int
    callback :account_name, [:pointer, :string, :string], :string
    callback :account_name_free, [:pointer, :pointer, :string], :void


    class OtrlMessageAppOps < FFI::Struct
      layout :policy, :policy,
      :create_privkey, :create_privkey,
      :is_logged_in, :is_logged_in,
      :inject_message, :inject_message,
      :notify, :notify,
      :display_otr_message, :display_otr_message,
      :update_context_list, :update_context_list,
      :protocol_name, :protocol_name,
      :protocol_name_free, :protocol_name_free,
      :new_fingerprint, :new_fingerprint,
      :write_fingerprints, :write_fingerprints,
      :gone_secure, :gone_secure,
      :gone_insecure, :gone_insecure,
      :still_secure, :still_secure,
      :log_message, :log_message,
      :max_message_size, :max_message_size,
      :account_name, :account_name,
      :account_name_free, :account_name_free
    end

    # proto.h
    typedef :uint, :otrl_policy

    enum :otrl_message_type, [
      :not_otr,
      :tagged_plain_text,
      :query,
      :dh_commit,
      :dh_key,
      :revealsig,
      :signature,
      :v1_keyexch,
      :data,
      :error,
      :unknown
    ]

    enum :otrl_fragment_result, [
      :unfragmented,
      :incomplete,
      :complete
    ]

    enum :otrl_fragment_policy, [
      :send_all,
      :send_all_but_first,
      :send_all_but_last
    ]

    # sm.h
    enum :next_expected_smp, [
      :expect1,
      :expect2,
      :expect3,
      :expect4,
      :expect5
    ]

    enum :otrl_smprog_state, [
      :ok,        0,
      :created,   -2,
      :failed,    -1,
      :succeeded, 1
    ]

    # userstate.h
    typedef :pointer, :otrl_user_state
  end
end
