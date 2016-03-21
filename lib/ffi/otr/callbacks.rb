# These are called from libotr, to be implemented by the application.
# There is already a basic implementation for {#create_privkey} and
# {#write_fingerprints}, so for minimal operation only {#inject_message}
# and {#display_otr_message} are required.
# To receive messages about missing callbacks, set the `:debug` option
# in your {UserState}.
module FFI::OTR::Callbacks

  # Return the OTR policy for the given context.
  def policy(opdata, context)
    @opts[:policy]
  end

  # Create a private key for the given accountname/protocol if desired.
  def create_privkey(opdata, account, protocol)
    if @opts[:privkey]
      debug "Generating private key for #{account} (#{protocol}). This may take a while."
      privkey_generate(@opts[:privkey], @account, @protocol)
      debug "Private key generated. Fingerprint is #{fingerprint}."
    else
      not_implemented
    end
  end

  # Report whether you think the given user is online.  Return 1 if
  # you think he is, 0 if you think he isn't, -1 if you're not sure.
  # If you return 1, messages such as heartbeats or other
  # notifications may be sent to the user, which could result in "not
  # logged in" errors if you're wrong.
  def is_logged_in(opdata, account, protocol, recipient)
    not_implemented
  end

  # Send the given IM to the given recipient from the given account/protocol.
  def inject_message(opdata, account, protocol, recipient, message)
    not_implemented
  end

  # Display a notification message for a particular accountname / protocol /
  # username conversation.
  def notify(opdata, level, account, protocol, user, title, primary, secondary)
    not_implemented
  end

  # OTR control message for a particular accountname /
  # protocol / username conversation.  Return 0 if you are able to
  # successfully display it.  If you return non-0 (or if this
  # function is NULL), the control message will be displayed inline,
  # as a received message, or else by using the above notify()
  # callback.
  def display_otr_message(opdata, account, protocol, user, msg)
    not_implemented
    0
  end

  # When the list of ConnContexts changes (including a change in state),
  # this is called so the UI can be updated
  def update_context_list(opdata)
    not_implemented
  end

  # Return a newly allocated string containing a human-friendly name for
  # the given protocol id
  def protocol_name(opdata, protocol)
    not_implemented
  end

  # Deallocate a string allocated by protocol_name
  def protocol_name_free(opdata, protocol_name)
    not_implemented
  end

  # A new fingerprint for the given user has been received.
  def new_fingerprint(opdata, userstate, account, protocol, from, fingerprint)
    not_implemented
  end

  # The list of known fingerprints has changed.  Write them to disk.
  def write_fingerprints(opdata)
    if @opts[:fingerprints]
      privkey_write_fingerprints(@opts[:fingerprints])
    else
      not_implemented
    end
  end

  # A ConnContext has entered a secure state
  def gone_secure(opdata, context)
    not_implemented
  end

  # A ConnContext has left a secure state.
  def gone_insecure(opdata, context)
    not_implemented
  end

  # We have completed an authentication, using the D-H keys we already knew.
  # is_reply indicates whether we initiated the AKE.
  def still_secure(opdata, context, is_reply, _)
    not_implemented
  end

  # Log a message.  The passed message will end in "\n".
  def log_message(opdata, message)
    debug message[0...-1]
  end

  # Find the maximum message size supported by this protocol.
  def max_message_size(opdata, context)
    @opts[:max_message_size]
  end

  # Return a newly allocated string containing a human-friendly representation
  # for the given account.
  def account_name(opdata, account, protocol)
    "#{protocol}://#{account}"
  end

  # Deallocate a string returned by {#account_name}.
  def account_name_free(opdata, account)
    not_implemented
  end

  # We received a request from the buddy to use the current "extra"
  # symmetric key. The key will be passed in symkey, of length
  # OTRL_EXTRAKEY_BYTES. The requested use, as well as use-specific
  # data will be passed so that the applications can communicate other
  # information (some id for the data transfer, for example).
  #
  # This is called when a remote buddy has specified a use for the current
  # symmetric key. If your application does not use the extra symmetric key
  # it does not need to provide an implementation for this operation.
  def received_symkey(opdata, context, use, usedata, usedatalen, symkey)
    not_implemented
  end

  # Return a string according to the error event. This string will then
  # be concatenated to an OTR header to produce an OTR protocol error
  # message. The following are the possible error events:
  # @param OTRL_ERRCODE_ENCRYPTION_ERROR
  #		occured while encrypting a message
  # @param OTRL_ERRCODE_MSG_NOT_IN_PRIVATE
  #		sent encrypted message to somebody who is not in
  #		a mutual OTR session
  # @param OTRL_ERRCODE_MSG_UNREADABLE
  #		sent an unreadable encrypted message
  # @param OTRL_ERRCODE_MSG_MALFORMED
  #		message sent is malformed
  def otr_error_message(opdata, context, err_code)
    not_implemented
  end

  # Deallocate a string returned by otr_error_message
  def otr_error_message_free(opdata, message)
    not_implemented
  end

  # Return a string that will be prefixed to any resent message. If this
  # function is not provided by the application then the default prefix,
  # "[resent]", will be used.
  #
  # These operations give the option of chosing an alternative to the
  # English string "[resent]", when a message is resent.
  def resent_msg_prefix(opdata, context)
    not_implemented
  end

  # Deallocate a string returned by resent_msg_prefix
  def resent_msg_prefix_free(opdata, prefix)
    not_implemented
  end

  # Update the authentication UI with respect to SMP events
  # These are the possible events:
  # @param OTRL_SMPEVENT_ASK_FOR_SECRET
  #			prompt the user to enter a shared secret. The sender application
  #			should call otrl_message_initiate_smp, passing NULL as the question.
  #			When the receiver application resumes the SM protocol by calling
  #			otrl_message_respond_smp with the secret answer.
  # @param OTRL_SMPEVENT_ASK_FOR_ANSWER
  #			(same as OTRL_SMPEVENT_ASK_FOR_SECRET but sender calls
  #			otrl_message_initiate_smp_q instead)
  # @param OTRL_SMPEVENT_CHEATED
  #			abort the current auth and update the auth progress dialog
  #			with progress_percent. otrl_message_abort_smp should be called to
  #			stop the SM protocol.
  # @param OTRL_SMPEVENT_INPROGRESS		and
  #	 OTRL_SMPEVENT_SUCCESS	and
  #	 OTRL_SMPEVENT_FAILURE			and
  #	 OTRL_SMPEVENT_ABORT
  #			update the auth progress dialog with progress_percent
  # @param OTRL_SMPEVENT_ERROR
  #			(same as OTRL_SMPEVENT_CHEATED)
  def handle_smp_event(opdata, smp_event, context, progress_percent, question)
    not_implemented
  end

  # Handle and send the appropriate message(s) to the sender/recipient
  # depending on the message events. All the events only require an opdata,
  # the event, and the context. The message and err will be NULL except for
  # some events (see below). The possible events are:
  #
  # @param OTRL_MSGEVENT_ENCRYPTION_REQUIRED
  #			Our policy requires encryption but we are trying to send
  #			an unencrypted message out.
  # @param OTRL_MSGEVENT_ENCRYPTION_ERROR
  #			An error occured while encrypting a message and the message
  #			was not sent.
  # @param OTRL_MSGEVENT_CONNECTION_ENDED
  #			Message has not been sent because our buddy has ended the
  #			private conversation. We should either close the connection,
  #			or refresh it.
  # @param OTRL_MSGEVENT_SETUP_ERROR
  #			A private conversation could not be set up. A gcry_error_t
  #			will be passed.
  # @param OTRL_MSGEVENT_MSG_REFLECTED
  #			Received our own OTR messages.
  # @param OTRL_MSGEVENT_MSG_RESENT
  #			The previous message was resent.
  # @param OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE
  #			Received an encrypted message but cannot read
  #			it because no private connection is established yet.
  # @param OTRL_MSGEVENT_RCVDMSG_UNREADABLE
  #			Cannot read the received message.
  # @param OTRL_MSGEVENT_RCVDMSG_MALFORMED
  #			The message received contains malformed data.
  # @param OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD
  #			Received a heartbeat.
  # @param OTRL_MSGEVENT_LOG_HEARTBEAT_SENT
  #			Sent a heartbeat.
  # @param OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR
  #			Received a general OTR error. The argument 'message' will
  #			also be passed and it will contain the OTR error message.
  # @param OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED
  #			Received an unencrypted message. The argument 'smessage' will
  #			also be passed and it will contain the plaintext message.
  # @param OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED
  #			Cannot recognize the type of OTR message received.
  def handle_msg_event(opdata, msg_event, context, message, err)
    not_implemented
  end

  # Create a instance tag for the given accountname/protocol if desired.
  def create_instag(opdata, account, protocol)
    if @opts[:instags]
      debug "Creating new instance tag for #{account},#{protocol}"
      otrl_instag_generate(@userstate, @opts[:instags], account, protocol)
    else
      not_implemented
    end
  end

  # TODO: figure out how these work. until then, leave them undefined.
  # # Called immediately before a data message is encrypted, and after a data
  # # message is decrypted. The OtrlConvertType parameter has the value
  # # OTRL_CONVERT_SENDING or OTRL_CONVERT_RECEIVING to differentiate these
  # # cases.
  # def convert_msg(opdata, context, convert_type, dest, src)
  #   not_implemented
  # end

  # # Deallocate a string returned by convert_msg.
  # def convert_free(opdata, context, dest)
  #   not_implemented
  # end

  private

  def not_implemented
    debug "#{caller[0].match(/`(.+)'$/)[1]} callback not implemented."
  end

  def debug(*args)
    $stderr.puts *args  if @opts[:debug]
  end

end
