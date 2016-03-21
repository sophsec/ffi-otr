$: << "../lib"

require 'fileutils'
require "ffi/otr"
FFI::OTR.otrl_init(4, 1, 1)

describe FFI::OTR do

  WHITESPACE_TAG = " \t  \t\t\t\t \t \t \t    \t\t  \t   \t\t  \t\t"
  before :each do
    FileUtils.rm_f("spec/fixtures/fingerprints.1.otr")
    FileUtils.rm_f("spec/fixtures/fingerprints.2.otr")
    @user1 = FFI::OTR::UserState.new("user1", "xmpp",
                               privkey: "spec/fixtures/keys.1.otr",
                               fingerprints: "spec/fixtures/prints.1.otr",
                               instags: "spec/fixtures/instags.2.otr",
                               debug: false)
    @user2 = FFI::OTR::UserState.new("user2", "xmpp",
                               privkey: "spec/fixtures/keys.2.otr",
                               fingerprints: "spec/fixtures/prints.2.otr",
                               instags: "spec/fixtures/instags.2.otr",
                               debug: false)
  end

  it "should create userstate" do
    expect(@user1.userstate.null?).to be(false)
    expect(@user1.ui_ops).to be_a(FFI::OTR::OtrlMessageAppOps)
  end

  it "should establish session" do
    # TAGGEDPLAINTEXT
    @message = @user1.sending("user2", "hi")
    expect(@message).to eql("hi#{WHITESPACE_TAG}")

    # DH_COMMIT
    expect(@user2).to receive(:inject_message) {|_, account, protocol, to, message|
      expect([account, protocol, to]).to eql(["user2", "xmpp", "user1"])
      expect(@message = message).to match(/\?OTR:/)
    }
    # Note that @message is still the one returned by @user1.sending
    expect(@user2.receiving("user1", @message)).to eql("hi")

    # DH_KEY
    expect(@user1).to receive(:inject_message) {|_, account, protocol, to, message|
      expect([account, protocol, to]).to eql(["user1", "xmpp", "user2"])
      expect(@message = message).to match(/\?OTR:/)
    }
    expect(@user1.receiving("user2", @message)).to be(nil)

    # REVEALSIG
    expect(@user2).to receive(:inject_message) {|_, account, protocol, to, message|
      expect([account, protocol, to]).to eql(["user2", "xmpp", "user1"])
      expect(@message = message).to match(/\?OTR:/)
    }
    expect(@user2.receiving("user1", @message)).to be(nil)

    # SIGNATURE
    expect(@user1).to receive(:gone_secure) # TODO

    expect(@user1).to receive(:inject_message) {|_, account, protocol, to, message|
      expect([account, protocol, to]).to eql(["user1", "xmpp", "user2"])
      expect(@message = message).to match(/\?OTR:/)
    }
    expect(@user1.receiving("user2", @message)).to be(nil)
    
    expect(@user2).to receive(:gone_secure) # TODO
    expect(@user2.receiving("user1", @message)).to be(nil)

    plain = "What's going on?"
    msg = @user1.sending("user2", plain)
    expect(msg).to match(/^?OTR:/)
    expect(msg).to_not match(plain)
    expect(@user2.receiving("user1", msg)).to eql(plain)
  
    10.times do |i|
      msg = @user1.sending("user2", "foo #{i}")
      expect(msg).to match(/\?OTR:/)
      expect(msg).to_not match("foo #{i}")
      expect(@user2.receiving("user1", msg)).to eql("foo #{i}")
      msg = @user2.sending("user1", "bar #{i}")
      expect(msg).to match(/\?OTR:/)
      expect(msg).to_not match("foo #{i}")
      expect(@user1.receiving("user2", msg)).to eql("bar #{i}")
    end

  end

  it "should get fingerprint" do
    expect(@user1.fingerprint).to eql("F501A951 B1C9789C 6240A89B 5E1A7B0A 7DC5C34C")
    expect(@user2.fingerprint).to eql("BB4EE861 8E26FD5C CBC7F19F 879A183C 2A6F437A")
  end

  describe :policy do

    describe :default do

      it "should add whitespace tag when sending first message" do
        expect(@user1).to_not receive(:inject_message)
        expect(@user1.sending("user2", "test")).to eql("test#{WHITESPACE_TAG}")
      end

      it "should initiate session when receiving whitespace tag" do
        expect(@user1).to receive(:inject_message) {|_, account, protocol, recipient, msg|
          expect(msg).to match(/\?OTR:/)
          expect(msg).to_not match("test") }
        expect(@user1.receiving("user2", "test#{WHITESPACE_TAG}")).to eql("test")
      end

    end

    describe :never do

      before(:each) { @user1.opts[:policy] = FFI::OTR::POLICY_NEVER }

      it "should not add whitespace tag when sending first message" do
        expect(@user1).to_not receive(:inject_message)
        expect(@user1.sending("user2", "test")).to eql("test")
      end

      it "should not initiate session when receiving whitespace tag" do
        expect(@user1).to_not receive(:inject_message)
        expect(@user1.receiving("user2", "test#{WHITESPACE_TAG}"))
          .to eql("test#{WHITESPACE_TAG}")
      end

    end

    describe :always do

      before(:each) { @user1.opts[:policy] |= FFI::OTR::POLICY_ALWAYS }

      it "should initiate session when sending first message" do
        expect(@user1).to_not receive(:inject_message)
        expect(@user1).to receive(:handle_msg_event) {|_, event, _, msg, err|
          expect([event, msg, err]).to eql([:encryption_required, nil, 0]) }
        expect(@user1.sending("user2", "text"))
          .to eql("?OTRv23?\n<b>user1</b> has requested an <a href=\"https://otr.cypherpunks.ca/\">Off-the-Record private conversation</a>.  However, you do not have a plugin to support that.\nSee <a href=\"https://otr.cypherpunks.ca/\">https://otr.cypherpunks.ca/</a> for more information.")
      end

      it "should warn user when receiving plain message" do
        expect(@user1).to receive(:handle_msg_event) {|opdata, event, context, msg, err|
          expect([event, msg, err]).to eql([:rcvdmsg_unrecognized, "text", 0]) }
        expect(@user1.receiving("user2", "text")).to be(nil)
      end

    end

  end

end
