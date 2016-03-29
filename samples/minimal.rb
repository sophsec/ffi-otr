require 'ffi/otr'

# Load the desired version of OTR
FFI::OTR.otrl_init 4, 1, 1

# Inherit a UserState to implement our callbacks
class UserState < FFI::OTR::UserState

  # OTR wants us to send a message
  def inject_message opdata, account, protocol, recipient, message
    user = recipient == "user1" ? USER1 : USER2
    user.receiving(account, message)
  end

end

# Create UserStates for two users
USER1 = UserState.new("user1", "xmpp",
                      privkey: "key1.otr",
                      fingerprints: "prints1.otr",
                      instags: "instags1.otr",
                     ) # debug: true)
USER2 = UserState.new("user2", "xmpp",
                      privkey: "key2.otr",
                      fingerprints: "prints2.otr",
                      instags: "instags2.otr",
                     ) # debug: true)

# User 1 sending a message (still in plain text, with whitespace tag added)
message = USER1.sending("user2", "Test message")

# User 2 receiving the message (initiating a session)
USER2.receiving("user1", message)

# Encrypted message from user 1 to user 2
message = USER1.sending("user2", "Test message 2")
puts message
puts USER2.receiving("user1", message)

# Encrypted message from user 2 to user 1
puts USER1.receiving("user2", USER2.sending("user1", "Test response"))
