# Wraps a OtrlUserState for convenient usage.
# Simply inherit from it, implement the {FFI::OTR::Callbacks} and pass your messages to {#sending} or {#receiving}.
class FFI::OTR::UserState

  include FFI::OTR
  include FFI::OTR::Callbacks

  DEFAULT_OPTS = {
    policy: POLICY_DEFAULT,
    max_message_size: 1024,
    debug: false,
  }

  attr_reader :userstate, :ui_ops, :account, :protocol, :opts

  # Initialize OTR UserState.
  #
  # @param [String] account account name
  # @param [String] protocol protocol name
  # @option opts [String] :privkey (nil) filename where the private key is stored
  # @option opts [String] :fingerprints (nil) filename where fingerprints are stored
  # @option opts [String] :instags (nil) filename where instance tags are stored
  # @option opts [Fixnum] :policy (POLICY_DEFAULT) OTR policy
  # @option opts [Fixnum] :max_message_size (1024) Max message size
  # @option opts [Boolean] :debug (false) Output debug messages for missing callbacks
  #
  # If the :privkey option is set, load the key and implement the
  # {#create_privkey} callback to generate it.
  #
  # If the :fingerprints options is set, load fingerprints and implement the
  # {#new_fingerprint} and {#write_fingerprints} callbacks.
  #
  # If the :instags option is set, load instance tags and implement the
  # {#create_instag} callback to generate it.
  #
  # Note: There is a bug in OTR versions <= 4.1.1 that makes it mandatory to have
  # a {#create_instag} callback. So specify the file name or implement it yourself.
  #
  # You can always override the callbacks, but if you don't specify those files,
  # you *must* implement them yourself.
  def initialize(account, protocol, opts = {})
    @account, @protocol = account, protocol
    @opts = DEFAULT_OPTS.merge(opts)
    @userstate = otrl_userstate_create
    otrl_privkey_read(@userstate, @opts[:privkey])  if @opts[:privkey]
    otrl_privkey_read_fingerprints(@userstate, @opts[:fingerprints], nil, nil)  if @opts[:fingerprints]
    otrl_instag_read(@userstate, @opts[:instags])  if @opts[:instags]
    setup_ui_ops
  end

  # Pass an outgoing message through OTR.
  #
  # @param [String] user account name of the user who will receive the message
  # @param [String] message the message to be sent
  # @param [String] opdata additional data that is passed to callbacks
  # @return [String] the modified message
  #
  # If there is an active OTR session with this user, the message will be encrypted.
  # Otherwise, the whitespace tag is appended, depending on the policy.
  def sending(user, message, opdata = nil)
    new_msg = FFI::MemoryPointer.new(:pointer); new_msg.autorelease = false
    unless otrl_message_sending(@userstate, @ui_ops, opdata,
                                @account, @protocol, user,
                                INSTAG_BEST, # instag
                                message,
                                nil, # tlvs
                                new_msg,
                                nil, # fragPolicy
                                nil, # contextp
                                nil, # add_appdata
                                nil # data
                               ) == 0
      raise "Error encrypting message. Do NOT send it."
    end
    res = (p = new_msg.read_pointer) && !p.null? ? p.read_string : message
    otrl_message_free(new_msg)
    res
  end

  # Pass an incoming message through OTR.
  #
  # @param [String] user account name of the user who sent the message
  # @param [String] message the message that was received
  # @param [String] opdata additional data that is passed to callbacks
  # @return [String] the modified message
  #
  # Decrypts the message and tries to establish new session if necessary.
  def receiving(user, message, opdata = nil)
    new_msg = FFI::MemoryPointer.new(:pointer); new_msg.autorelease = false
    unless otrl_message_receiving(@userstate, @ui_ops, opdata,
        @account, @protocol, user, message, new_msg, nil, nil, nil, nil) == 0
      return # ignore internal messages
    end
    res = (p = new_msg.read_pointer) && !p.null? ? p.read_string : message
    otrl_message_free(new_msg)
    res
  end

  # Get the fingerprint of this userstates private key.
  def fingerprint
    fp = FFI::MemoryPointer.new(:buffer_out, 45)
    unless otrl_privkey_fingerprint(@userstate, fp, @account, "xmpp")
      raise "Error getting fingerprint."
    end
    fp.read_string
  end

  private

  # Setup the OtrlMessageAppOps with our callbacks.
  def setup_ui_ops
    @ui_ops = OtrlMessageAppOps.new
    @ui_ops.layout.fields.each do |field|
      if respond_to?(field.name)
        @ui_ops[field.name] = ->(*a) {
          send(field.name, *a) }
      end
    end
  end

  # You can call any `otrl_*` method without the `otrl_*`-prefix, and the
  # userstate is passed in as the first argument. For example:
  #  userstate.privkey_write_fingerprints("fingerprints.otr")
  # @note This only works for methods that take the userstate as first argument.
  def method_missing(name, *args)
    n = "otrl_#{name}"
    respond_to?(n) ? send(n, @userstate, *args) : super(name, *args)
  end

  # Make #respond_to? and #method happy (see #method_missing).
  def respond_to_missing?(name, *)
    methods.include?("otrl_#{name}") || super
  end

end
