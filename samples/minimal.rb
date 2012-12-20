require 'ffi/otr'

# Load the desired version of OTR
FFI::OTR.otrl_init 3, 2, 1

# Inherit a UserState to implement our callbacks
class UserState < FFI::OTR::UserState

  # OTR wants us to send a message
  def inject_message opdata, account, protocol, recipient, message
    user = recipient == "user1" ? USER1 : USER2
    user.receiving(account, message)
  end

  # OTR wants us to display a message
  def display_otr_message opdata, account, protocol, from, msg
    puts msg
  end

end

# Create UserStates for two users
USER1 = UserState.new("user1", "xmpp", privkey: "key1.otr", fingerprints: "prints1.otr")
USER2 = UserState.new("user2", "xmpp", privkey: "key2.otr", fingerprints: "prints2.otr")

# User 1 sending a message (still in plain text, with whitespace tag added)
message = USER1.sending("user2", "Test message")

# User 2 receiving the message (initiating a session)
USER2.receiving("user1", message)

# Encrypted message from user 1 to user 2
puts USER2.receiving("user1", USER1.sending("user2", "Test message 2"))

# Encrypted message from user 2 to user 1
puts USER1.receiving("user2", USER2.sending("user1", "Test response"))
