require 'ffi'

module FFI
  module OTR
    extend FFI::Library

    typedef :uint, :gpg_error_t
    typedef :gpg_error_t, :gcry_error_t
    typedef :pointer, :gcry_mpi_t
    typedef :pointer, :gcry_md_hd_t
    typedef :pointer, :gcry_cipher_hd_t
    typedef :pointer, :gcry_sexp_t

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
      :ok, 0,
      :created, -2,
      :failed, -1,
      :succeeded, 1
    ]

    # userstate.h
    typedef :pointer, :otrl_user_state
  end
end
