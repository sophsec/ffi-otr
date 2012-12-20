$: << "../lib"

require 'fileutils'
require "ffi/otr"
FFI::OTR.otrl_init(3, 2, 1)

describe FFI::OTR do

  include FFI::OTR

  WHITESPACE_TAG = " \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t "
  before :each do
    @user1 = FFI::OTR::UserState.new("user1", "xmpp", privkey: "spec/fixtures/keys.1.otr")
    @user2 = FFI::OTR::UserState.new("user2", "xmpp", privkey: "spec/fixtures/keys.2.otr")
  end

  it "should create userstate" do
    @user1.userstate.null?.should == false
    @user1.ui_ops.should be_a(FFI::OTR::OtrlMessageAppOps)
  end

  it "should establish session" do
    @message = @user1.sending("user2", "hi")
    @message.should == "hi#{WHITESPACE_TAG}"
    @user2.should_receive(:inject_message) {|_, account, protocol, to, message|
      [account, protocol, to].should == ["user2", "xmpp", "user1"]
      (@message = message).should =~ /\?OTR:/
    }
    @user2.receiving("user1", @message).should == "hi"

    @user1.should_receive(:inject_message) {|_, account, protocol, to, message|
      [account, protocol, to].should == ["user1", "xmpp", "user2"]
      (@message = message).should =~ /\?OTR:/
    }
    @user1.receiving("user2", @message).should == nil

    @user2.should_receive(:inject_message) {|_, account, protocol, to, message|
      [account, protocol, to].should == ["user2", "xmpp", "user1"]
      (@message = message).should =~ /\?OTR:/
    }
    @user2.receiving("user1", @message).should == nil

    @user1.should_receive(:new_fingerprint) {|_, _, account, protocol, from, fingerprint|
      [account, protocol, from].should == ["user1", "xmpp", "user2"]
      fingerprint.should == "\xBBN\xE8a\x8E&\xFD\\\xCB\xC7\xF1\x9F\x87\x9A\x18<*oCz"
    }
    @user1.should_receive(:write_fingerprints) {
      @user1.privkey_write_fingerprints("spec/fixtures/fingerprints.1.otr") }
    @user1.should_receive(:gone_secure)
    @user1.should_receive(:inject_message) {|_, account, protocol, to, message|
      [account, protocol, to].should == ["user1", "xmpp", "user2"]
      (@message = message).should =~ /\?OTR:/
    }
    @user1.receiving("user2", @message).should == nil

    @user2.should_receive(:new_fingerprint) {|_, _, account, protocol, from, fingerprint|
      [account, protocol, from].should == ["user2", "xmpp", "user1"]
      fingerprint.should == "\xF5\x01\xA9Q\xB1\xC9x\x9Cb@\xA8\x9B^\x1A{\n}\xC5\xC3L\x01"
    }
    @user2.should_receive(:write_fingerprints) {
      @user2.privkey_write_fingerprints("spec/fixtures/fingerprints.2.otr") }
    @user2.should_receive(:gone_secure)
    @user2.receiving("user1", @message).should == nil


    m = @user1.sending("user2", "yes, of course!")
    m.should =~ /\?OTR:/
    @user2.receiving("user1", m).should =~ /yes/

    10.times do |i|
      msg = @user1.sending("user2", "foo #{i}")
      msg.should =~ /\?OTR:/; msg[/foo #{i}/].should == nil
      @user2.receiving("user1", msg).should == "foo #{i}"
      msg = @user2.sending("user1", "bar #{i}")
      msg.should =~ /\?OTR:/; msg[/bar #{i}/].should == nil
      @user1.receiving("user2", msg).should == "bar #{i}"
    end

    FileUtils.rm_f("spec/fixtures/fingerprints.1.otr")
    FileUtils.rm_f("spec/fixtures/fingerprints.2.otr")
  end

  it "should get fingerprint" do
    @user1.fingerprint.should == "F501A951 B1C9789C 6240A89B 5E1A7B0A 7DC5C34C"
    @user2.fingerprint.should == "BB4EE861 8E26FD5C CBC7F19F 879A183C 2A6F437A"
  end

  describe :policy do

    describe :default do

      it "should add whitespace tag when sending first message" do
        @user1.sending("user2", "test").should == "test#{WHITESPACE_TAG}"
      end

      it "should initiate session when receiving whitespace tag" do
        @user1.should_receive(:inject_message)
        @user1.receiving("user2", "test#{WHITESPACE_TAG}").should == "test"
      end

    end

    describe :never do

      before(:each) { @user1.opts[:policy] = FFI::OTR::POLICY_NEVER }

      it "should not add whitespace tag when sending first message" do
        @user1.sending("user2", "test").should == "test"
      end

      it "should not initiate session when receiving whitespace tag" do
        @user1.should_not_receive(:inject_message)
        @user1.receiving("user2", "test#{WHITESPACE_TAG}").should == "test#{WHITESPACE_TAG}"
      end

    end

    describe :always do

      before(:each) { @user1.opts[:policy] |= FFI::OTR::POLICY_ALWAYS }

      it "should initiate session when sending first message" do
        @user1.should_receive(:display_otr_message) {|_, account, protocol, from, msg|
          [account, protocol, from].should ==  ["user1", "xmpp", "user2"]
          msg.should == "Attempting to start a private conversation..."
        }
        @user1.sending("user2", "text").should == "?OTR?v2?\n<b>user1</b> has requested an <a href=\"http://otr.cypherpunks.ca/\">Off-the-Record private conversation</a>.  However, you do not have a plugin to support that.\nSee <a href=\"http://otr.cypherpunks.ca/\">http://otr.cypherpunks.ca/</a> for more information."
      end

      it "should warn user when receiving plain message" do
        @user1.should_receive(:display_otr_message) {|_, account, protocol, from, msg|
          [account, protocol, from].should ==  ["user1", "xmpp", "user2"]
          msg.should == "<b>The following message received from user2 was <i>not</i> encrypted: [</b>text<b>]</b>"
        }
        @user1.receiving("user2", "text").should == nil
      end

    end

  end

end
