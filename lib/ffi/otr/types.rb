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

    callback :policy_cb, [:pointer, :pointer], :uint
    callback :create_privkey_cb, [:pointer, :string, :string], :void
    callback :is_logged_in_cb, [:pointer, :string, :string, :string], :void
    callback :inject_message_cb, [:pointer, :string, :string, :string, :string], :void
    callback :notify_cb, [:pointer, :pointer, :string, :string, :string, :string, :string, :string], :void
    callback :display_otr_message_cb, [:pointer, :string, :string, :string, :string], :void
    callback :update_context_list_cb, [:pointer], :void
    callback :protocol_name_cb, [:pointer, :string], :void
    callback :protocol_name_free_cb, [:pointer, :string], :void
    callback :new_fingerprint_cb, [:pointer, :pointer, :string, :string, :string, :string], :void
    callback :write_fingerprints_cb, [:pointer], :void
    callback :gone_secure_cb, [:pointer, :pointer, :int], :void
    callback :gone_insecure_cb, [:pointer, :pointer], :void
    callback :still_secure_cb, [:pointer, :pointer, :int, :int], :void
    callback :log_message_cb, [:pointer, :string], :void
    callback :max_message_size_cb, [:pointer, :pointer], :int
    callback :account_name_cb, [:pointer, :string, :string], :string
    callback :account_name_free_cb, [:pointer, :pointer, :string], :void


    class OtrlMessageAppOps < FFI::Struct
      layout :policy_cb, :policy_cb,
      :create_privkey_cb, :create_privkey_cb,
      :is_logged_in_cb, :is_logged_in_cb,
      :inject_message_cb, :inject_message_cb,
      :notify_cb, :notify_cb,
      :display_otr_message_cb, :display_otr_message_cb,
      :update_context_list_cb, :update_context_list_cb,
      :protocol_name_cb, :protocol_name_cb,
      :protocol_name_free_cb, :protocol_name_free_cb,
      :new_fingerprint_cb, :new_fingerprint_cb,
      :write_fingerprints_cb, :write_fingerprints_cb,
      :gone_secure_cb, :gone_secure_cb,
      :gone_insecure_cb, :gone_insecure_cb,
      :still_secure_cb, :still_secure_cb,
      :log_message_cb, :log_message_cb,
      :max_message_size_cb, :max_message_size_cb,
      :account_name_cb, :account_name_cb,
      :account_name_free_cb, :account_name_free_cb
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
