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
      debug "Generating private key. This may take a while."
      privkey_generate(@opts[:privkey], @account, @protocol)
      debug "Private key generated. Fingerprint is #{fingerprint}."
    else
      super
    end
  end

  # Report whether you think the given user is online.  Return 1 if
  # you think he is, 0 if you think he isn't, -1 if you're not sure.
  # If you return 1, messages such as heartbeats or other
  # notifications may be sent to the user, which could result in "not
  # logged in" errors if you're wrong.
  def is_logged_in(opdata, account, protocol, recipient)
    debug "is_logged_in callback not implemented."
  end

  # Send the given IM to the given recipient from the given account/protocol.
  def inject_message(opdata, account, protocol, recipient, message)
    debug "inject_message callback not implemented."
  end

  # Display a notification message for a particular accountname / protocol /
  # username conversation.
  def notify(opdata, level, account, protocol, user, title, primary, secondary)
    debug "notify callback not implemented."
  end

  # OTR control message for a particular accountname /
  # protocol / username conversation.  Return 0 if you are able to
  # successfully display it.  If you return non-0 (or if this
  # function is NULL), the control message will be displayed inline,
  # as a received message, or else by using the above notify()
  # callback.
  def display_otr_message(opdata, account, protocol, user, msg)
    debug "display_otr_message callback not implemented."
    0
  end

  # When the list of ConnContexts changes (including a change in state),
  # this is called so the UI can be updated
  def update_context_list(opdata)
    debug "update_context_list callback not implemented."
  end

  # Return a newly allocated string containing a human-friendly name for
  # the given protocol id
  def protocol_name(opdata, protocol)
    debug "protocol_name callback not implemented."
  end

  # Deallocate a string allocated by protocol_name
  def protocol_name_free(opdata, protocol_name)
    debug "protocol_name_free callback not implemented."
  end

  # A new fingerprint for the given user has been received.
  def new_fingerprint(opdata, userstate, account, protocol, from, fingerprint)
    debug "new_fingerprint callback not implemented."  unless @opts[:fingerprints]
  end

  # The list of known fingerprints has changed.  Write them to disk.
  def write_fingerprints(opdata)
    if @opts[:fingerprints]
      privkey_write_fingerprints(@opts[:fingerprints])
    else
      debug "write_fingerprints callback not implemented."
    end
  end

  # A ConnContext has entered a secure state
  def gone_secure(opdata, context, _)
    debug "gone_secure callback not implemented."
  end

  # A ConnContext has left a secure state.
  def gone_insecure(opdata, context)
    debug "gone_insecure callback not implemented."
  end

  # We have completed an authentication, using the D-H keys we already knew.
  # is_reply indicates whether we initiated the AKE.
  def still_secure(opdata, context, is_reply, _)
    debug "still_secure callback not implemented."
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
    debug "account_name_free callback not implemented."
  end

  private

  def debug(*args)
    $stderr.puts *args  if @opts[:debug]
  end

end
