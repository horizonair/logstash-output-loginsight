# encoding: utf-8
# Copyright © 2017 VMware, Inc. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

require "logstash/outputs/http"
require "time"
require_relative "common"
require_relative "logger"
require_relative "packet"


# This output plugin is used to send Events to a VMware vRealize Log Insight cluster,
# preserving existing fields on Events as key=value fields. Timestamps are transmitted
# as milliseconds-since-epoch UTC.

# output { loginsight { host => ["10.11.12.13"] } }

class LogStash::Outputs::Loginsight < LogStash::Outputs::Http

  config_name "loginsight"


  config :host, :validate => :string, :required => true
  config :port, :validate => :number, :default => 9543
  config :proto, :validate => :string, :default => 'https'
  config :uuid, :validate => :string, :default => nil

  config :verify, :default => true, :deprecated => 'Deprecated alias for "ssl_certificate_validation". Insecure. For self-signed certs, use openssl s_client to save server\'s certificate to a PEM-formatted file. Then pass the filename in "cacert" option.'
  config :ca_file, :validate => :string, :default => nil, :deprecated => 'Deprecated alias for "cacert", specify path to PEM-formatted file.'

  config :flush_size, :validate => :number, :default => 1, :obsolete => 'Has no effect. Events are sent without delay.'
  config :idle_flush_time, :validate => :number, :default => 1, :obsolete => 'Has no effect. Events are sent without delay.'

  # Fields that will be renamed or dropped.
  config :adjusted_fields, :validate => :hash, :default => {
      'hostname' => 'host',  # unlikely to be present, preserve anyway
      'host' => 'hostname',  # desired change
      '@version' => nil,  # drop
      '@timestamp' => nil,  # drop, already mapped to "timestamp" in event_hash
      'message' => nil,  # drop, already mapped to "text" in event_hash
      'timestamp' => 'timestamp_',  # Log Insight will refuse events with a "timestamp" field.
      'beat_name' => nil,
      #'beat_hostname' => nil,
      'beat_version' => nil,
      #'tags' => nil,
      'source' => 'filepath',
      'prospector_type' => nil,
      'offset' => nil
  }

  config :url, :validate => :string, :default => nil, :deprecated => 'Use "host", "port", "proto" and "uuid" instead.'


  # Remove configuration options from superclass that don't make sense for this plugin.
  @config.delete('http_method')  # CFAPI is post-only
  @config.delete('format')
  @config.delete('message')

  public
  def register

    if @cacert.nil?
      @cacert = @ca_file
    end

    unless @verify.nil?
      @ssl_certificate_validation = @verify
    end

    # Hard-wired options
    @http_method = 'post'
    @format = 'json'
    @content_type = 'application/json'

    @uuid ||= ( @id or 0 )  # Default UUID
    @logger.debug("Starting up agent #{@uuid}")

    if @url.nil?
      @url = "#{@proto}://#{@host}:#{@port}/api/v1/events/ingest/#{@uuid}"
    end

    super

  end # def register

  # override function from parent class, Http, removing other format modes
  def event_body(event)
    LogStash::Json.dump(cfapi([event]))
  end

  def timestamp_in_milliseconds(timestamp)
    (timestamp.to_f * 1000).to_i
  end

  def get_value(name, event)
    LogStash::Json.dump(event.get(name))
  end

  # Frame the events in the hash-array structure required by Log Insight
  def cfapi(events)
    messages = []

    # For each event
    events.each do |event|
      event_hash = {
        'timestamp' => timestamp_in_milliseconds(event.get('@timestamp'))
      }
      @logger.debug("plugin event received [#{event}]")
      metadata = event.get('[@metadata]')
      if metadata.has_key? "beat"
        # This is a beats message, process it.      
        @logger.debug("metadata [#{event.get('[@metadata]')}]")
        @logger.debug("process beat event => #{event.get('beat')}")

        # We will parse the beat message similar to syslog to get the time and hostname
        p = parse_beat(event.get('message'))

        # Create an outbound event; this can be serialized to json and sent
        event_hash['text'] = (p.content or '')

        # Map fields from the event to the desired form
        @logger.debug("Event.to_hash => #{event.to_hash}")
        @logger.debug("Event.to_hash.merge(to_hash(p)) => #{event.to_hash.merge(to_hash(p))}")
        fields_hash = merge_hash(event.to_hash.merge(to_hash(p)))
        
      else
        # Create an outbound event; this can be serialized to json and sent
        p = parse_syslog(event.get('message'))
        event_hash['text'] = (p.content or '')
        fields_hash = merge_hash(to_hash(p))
        
      end # is non-beats message
      event_hash['fields'] = fields_hash
          .reject { |key,value| @adjusted_fields.has_key?(key) and @adjusted_fields[key] == nil }  # drop banned fields
          .map {|k,v| [ @adjusted_fields.has_key?(k) ? @adjusted_fields[k] : k,v] }  # rename fields
          .map {|k,v| { 'name' => (safefield(k)), 'content' => v } }  # Convert a hashmap {k=>v, k2=>v2} to a list [{name=>k, content=>v}, {name=>k2, content=>v2}]

      @logger.debug("Hash [#{event_hash}]")
      messages.push(event_hash)
    end # events.each do

    { 'events' => messages }  # Framing required by CFAPI.
  end # def cfapi

  # Return a copy of the fieldname with non-alphanumeric characters removed.
  def safefield(fieldname)
    fieldname.gsub(/[^a-zA-Z0-9_]/, '')  # TODO: Correct pattern for a valid fieldname. Must deny leading numbers.
  end

  def to_hash(packet)
    hash = {}
    hash["host"] = packet.hostname
    hash["severity"] = packet.severity ? packet.severity : SEVERITIES['notice']
    hash
  end

  # Recursively merge a nested dictionary into a flat dictionary with dotted keys.
  def merge_hash(hash, prelude = nil)
    hash.reduce({}) do |acc, kv|
      k, v = kv
      generated_key = prelude ? "#{prelude}_#{k}" : k.to_s
      #puts("Generated key #{generated_key}")
      if v.is_a?(Hash)
        acc.merge!(merge_hash(v, generated_key))
      elsif v.is_a?(Array)
        acc[generated_key] = v.to_s
      else
        acc[generated_key] = v
      end
      acc
    end
  end

  def parse_beat(msg, origin=nil)
    packet = Packet.new
    original_msg = msg.dup
    time = parse_time(msg)
    if time
      packet.time = Time.parse(time)
    else
      packet.time = Time.now
    end
    msg = msg.strip
    hostname = parse_hostname(msg)
    packet.hostname = hostname || origin
    if m = msg.match(/^(\w+)(: | )(.*)$/)
      packet.tag = m[1]
      packet.content = m[3]
    else
      packet.tag = 'unknown'
      packet.content = msg.strip
    end
    packet
  end

  def parse_syslog(msg, origin=nil)
    packet = Packet.new
    original_msg = msg.dup
    pri = parse_pri(msg)
    if pri and (pri = pri.to_i).is_a? Integer and (0..191).include?(pri)
      packet.pri = pri
    else
      # If there isn't a valid PRI, treat the entire message as content
      packet.pri = 13
      packet.time = Time.now
      packet.hostname = origin || 'unknown'
      packet.content = original_msg
      return packet
    end
    time = parse_time(msg)
    if time
      packet.time = Time.parse(time)
    else
      packet.time = Time.now
    end
    msg = msg.strip
    hostname = parse_hostname(msg)
    packet.hostname = hostname || origin
    if m = msg.match(/^(\w+)(: | )(.*)$/)
      packet.tag = m[1]
      packet.content = m[3]
    else
      packet.tag = 'unknown'
      packet.content = msg.strip
    end
    packet
  end
  
  private
  def parse_pri(msg)
    pri = msg.slice!(/<(\d\d?\d?)>/)
    pri = pri.slice(/\d\d?\d?/) if pri
    if !pri or (pri =~ /^0/ and pri !~ /^0$/)
      return nil
    else
      return pri
    end
  end
  
  def parse_time(msg)
    time = msg.slice!(/^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s(\s|[1-9])\d\s\d\d:\d\d:\d\d\s/)
    if (time)
      return time
    else
      # Parse ISO8601 date
      time = msg.slice!(/^\d\d\d\d(-\d\d(-\d\d(T\d\d:\d\d(:\d\d)?(\.\d+)?(([+-]\d\d:\d\d)|Z)?)?)?)?/)
      if (time)
        return time
      else
        # Parse vCenter time (prefix with digit)
        return msg.slice!(/^\d \d\d\d\d(-\d\d(-\d\d(T\d\d:\d\d(:\d\d)?(\.\d+)?(([+-]\d\d:\d\d)|Z)?)?)?)?/)
      end 
    end
  end
  
  def parse_hostname(msg)
    msg.slice!(/^[\x21-\x7E]+/).rstrip
  end
end # class LogStash::Outputs::Loginsight
