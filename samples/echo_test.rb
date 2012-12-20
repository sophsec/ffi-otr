require 'xmpp4r-simple'
require 'ffi/otr'

FFI::OTR.otrl_init(3, 2, 1)

if ARGV.empty?
  puts "usage: #{__FILE__} <jid> <pass>"
  exit 0
end
jid, pass = *ARGV

class MyUserState < FFI::OTR::UserState

  def initialize jabber, account, protocol, opts = {}
    @jabber = jabber
    super(account, protocol,
          privkey: "echo_test.key.otr",
          fingerprints: "echo_test.prints.otr",
          policy: FFI::OTR::POLICY_ALWAYS,
          debug: true)
  end

  def inject_message opdata, account, protocol, recipient, message
    @jabber.deliver(recipient, message)
  end

  def display_otr_message opdata, account, protocol, from, msg
    puts "#{from}: #{msg}"
  end

end

jabber = Jabber::Simple.new(jid, pass)
otr = MyUserState.new(jabber, jid, "xmpp")

loop do 
  jabber.received_messages do |msg|
    next  unless message = otr.receiving(msg.from.to_s, msg.body)
    puts "#{msg.from}: #{message}"

    response = otr.sending(msg.from.to_s, message)
    jabber.deliver(msg.from, response)
  end
  sleep 0.1
end
