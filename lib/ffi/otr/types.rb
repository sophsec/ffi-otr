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
    typedef :pointer,     :opdata
    typedef :pointer,     :context
    typedef :pointer,     :user_state

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

    # instag.h
    INSTAG_MASTER = 0
    INSTAG_BEST = 1
    INSTAG_RECENT = 2
    INSTAG_RECENT_RECEIVED = 3
    INSTAG_RECENT_SENT = 4

    MIN_VALID_INSTAG = 0x100

    typedef :uint, :instag_t
    typedef :instag_t, :otrl_instag_t

    class InsTag < FFI::Struct
      layout :next, :pointer,
             :tous, :pointer,
             :accountname, :string,
             :protocol, :string,
             :instag, :instag_t
    end

    # message.h

    enum :error_code, [
      :none,
      :encryption_error,
      :msg_not_in_private,
      :msg_unreadable,
      :msg_malformed
    ]

    enum :smp_event, [
      :none,
      :error,
      :abort,
      :cheated,
      :ask_for_answer,
      :ask_for_secret,
      :in_progress,
      :success,
      :failure
    ]

    enum :message_event, [
      :none,
      :encryption_required,
      :encryption_error,
      :connection_ended,
      :setup_error,
      :msg_reflected,
      :rcvdmsg_not_in_private,
      :rcvdmsg_unreadable,
      :rcvdmsg_malformed,
      :log_heartbeat_rcvd,
      :log_heartbeat_sent,
      :rcvdmsg_general_err,
      :rcvdmsg_unencrypted,
      :rcvdmsg_unrecognized
    ]

    enum :notify_level, [
      :error,
      :warning,
      :info
    ]

    enum :convert_type, [
      :sending,
      :receiving
    ]

    # OtrlPolicy (*policy)(void *opdata, ConnContext *context);
    callback :policy, [:opdata, :context], :uint

    # void (*create_privkey)(void *opdata, const char *accountname,
    #   const char *protocol);
    callback :create_privkey, [:opdata, :string, :string], :void

    # int (*is_logged_in)(void *opdata, const char *accountname,
    #   const char *protocol, const char *recipient);
    callback :is_logged_in, [:opdata, :string, :string, :string], :void

    # void (*inject_message)(void *opdata, const char *accountname,
    #   const char *protocol, const char *recipient, const char *message);
    callback :inject_message, [:opdata, :string, :string, :string, :string], :void

    # void (*update_context_list)(void *opdata);
    callback :update_context_list, [:opdata], :void

    # void (*new_fingerprint)(void *opdata, OtrlUserState us,
    #   const char *accountname, const char *protocol,
    #   const char *username, unsigned char fingerprint[20]);
    callback :new_fingerprint, [:opdata, :user_state, :string, :string, :string, :string], :void

    # void (*write_fingerprints)(void *opdata);
    callback :write_fingerprints, [:opdata], :void

    # void (*gone_secure)(void *opdata, ConnContext *context);
    callback :gone_secure, [:opdata, :context], :void

    # void (*gone_insecure)(void *opdata, ConnContext *context);
    callback :gone_insecure, [:opdata, :context], :void

    # void (*still_secure)(void *opdata, ConnContext *context, int is_reply);
    callback :still_secure, [:opdata, :context, :int, :int], :void

    # int (*max_message_size)(void *opdata, ConnContext *context);
    callback :max_message_size, [:opdata, :context], :int

    # const char *(*account_name)(void *opdata, const char *account,
    #   const char *protocol);
    callback :account_name, [:opdata, :string, :string], :string

    # void (*account_name_free)(void *opdata, const char *account_name);
    callback :account_name_free, [:opdata, :pointer, :string], :void

    # void (*received_symkey)(void *opdata, ConnContext *context,
    #   unsigned int use, const unsigned char *usedata,
    #   size_t usedatalen, const unsigned char *symkey);
    callback :received_symkey, [:opdata, :context, :int, :string, :int, :string], :void

    # const char *(*otr_error_message)(void *opdata, ConnContext *context,
    #   OtrlErrorCode err_code);
    callback :otr_error_message, [:opdata, :context, :error_code], :string

    # void (*otr_error_message_free)(void *opdata, const char *err_msg);
    callback :otr_error_message_free, [:opdata, :string], :void

    # const char *(*resent_msg_prefix)(void *opdata, ConnContext *context);
    callback :resent_msg_prefix, [:opdata, :context], :string

    # void (*resent_msg_prefix_free)(void *opdata, const char *prefix);
    callback :resent_msg_prefix_free, [:opdata, :string], :void

    # void (*handle_smp_event)(void *opdata, OtrlSMPEvent smp_event, ConnContext *context, unsigned short progress_percent, char *question);
    callback :handle_smp_event, [:opdata, :smp_event, :context, :int, :string], :void

    # void (*handle_msg_event)(void *opdata, OtrlMessageEvent msg_event,
    #  ConnContext *context, const char *message,  gcry_error_t err);
    callback :handle_msg_event, [:opdata, :message_event, :context, :string, :gcry_error_t], :void

    # void (*create_instag)(void *opdata, const char *accountname, const char *protocol);
    callback :create_instag, [:opdata, :string, :string], :void

    # void (*convert_msg)(void *opdata, ConnContext *context,
	  #   OtrlConvertType convert_type, char ** dest, const char *src);
    callback :convert_msg, [:opdata, :context, :convert_type, :pointer, :string], :void

    # void (*convert_free)(void *opdata, ConnContext *context, char *dest);
    callback :convert_free, [:opdata, :context, :string], :void

    # void (*timer_control)(void *opdata, unsigned int interval);
    callback :timer_control, [:opdata, :uint], :void

    class OtrlMessageAppOps < FFI::Struct
      layout(*[
               :policy,
               :create_privkey,
               :is_logged_in,
               :inject_message,
               :update_context_list,
               :new_fingerprint, :write_fingerprints,
               :gone_secure, :gone_insecure, :still_secure,
               :max_message_size,
               :account_name, :account_name_free,
               :received_symkey,
               :otr_error_message, :otr_error_message_free,
               :resent_msg_prefix, :resent_msg_prefix_free,
               :handle_smp_event, :handle_msg_event,
               :create_instag,
               :convert_msg, :convert_free,
               :timer_control,
             ].map {|e| [e, e]}.flatten)
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
