require 'raven'

LEVEL_TRACE = 0
LEVEL_DEBUG = 1
LEVEL_INFO  = 2
LEVEL_WARN  = 3
LEVEL_ERROR = 4
LEVEL_FATAL = 5

class Fluent::SentryOutput < Fluent::BufferedOutput
  Fluent::Plugin.register_output('sentry', self)

  include Fluent::HandleTagNameMixin

  LOG_LEVEL = %w(fatal error warn info debug trace)
  EVENT_KEYS = %w(message timestamp time_spent level logger culprit server_name release tags platform sdk device)
  DEFAULT_HOSTNAME_COMMAND = 'hostname'
  
  config_param :default_level, :string, :default => 'error'
  config_param :log_level, :string, :default => 'warn'
  config_param :default_logger, :string, :default => 'fluentd'
  config_param :endpoint_url, :string
  config_param :flush_interval, :time, :default => 0
  config_param :hostname_command, :string, :default => 'hostname'

  def initialize
    require 'time'
    @log_level_int = str_to_level(@log_level)

    super
  end

  def configure(conf)
    super

    if @endpoint_url.nil?
      raise Fluent::ConfigError, "sentry: missing parameter for 'endpoint_url'"
    end

    unless LOG_LEVEL.include?(@default_level)
      raise Fluent::ConfigError, "sentry: unsupported default reporting log level for 'default_level'"
    end

    hostname_command = @hostname_command || DEFAULT_HOSTNAME_COMMAND
    @hostname = `#{hostname_command}`.chomp

    @configuration = Raven::Configuration.new
    @configuration.server = @endpoint_url
    @configuration.server_name = @hostname
    @configuration.logger.level = Raven::Logger::WARN
    @client = Raven::Client.new(@configuration)
  end

  def start
    super
  end

  def format(tag, time, record)
    [tag, time, record].to_msgpack
  end

  def shutdown
    super
  end

  def write(chunk)
    chunk.msgpack_each do |tag, time, record|
      begin
        level = tag.split('.').last.downcase
        if (LOG_LEVEL.include?(level) && (str_to_level(level) >= @log_level_int))
          notify_sentry(tag, time, record, level)
        end
      rescue => e
        $log.error("Sentry Error:", :error_class => e.class, :error => e.message)
      end
    end
  end

  def notify_sentry(tag, time, record, level)
    event = Fluent::GFRavenEvent.new(
      :configuration => @configuration,
      :context => Raven::Context.new,
      :message => record['message'],
      :tag => tag
    )
        
    event.timestamp = record['timestamp<ts>'] ? Time.strptime(record['timestamp<ts>'].to_s, '%Q').utc.strftime('%Y-%m-%dT%H:%M:%S') : Time.at(time).utc.strftime('%Y-%m-%dT%H:%M:%S')
    event.time_spent = record['time_spent'] || nil
    event.level = level || @default_level
    event.logger = record['service'] || @default_logger
    event.culprit = record['culprit'] || nil
    event.server_name = record['server_name'] || @hostname
    event.release = record['release'] if record['release']
    event.tags = event.tags.merge({ :tag => tag }.merge(record['tags'] || {}))
    event.extra = record.reject{ |key| EVENT_KEYS.include?(key) }
    @client.send_event(event)
  end
end

class Fluent::GFRavenEvent < Raven::Event
  attr_accessor :tag
  
  def initialize(init = {})
    if init['tag']
      _tag = init['tag']
      init.delete('tag')
      super
      @tag = _tag
    else
      super
    end
  end
  
  def to_hash
    data = super
    data['platform'] = determine_platform(@tag)
    return data
  end
end

def determine_platform(record_tag)
  tag = record_tag.downcase
  if tag.include?("csharp-appender")
    return "csharp"
  elsif tag.include? ("lumberjack")
    return "node"
  elsif (tag.include?("logback") || tag.include?("log4j"))
    return "java"
  else
    return "other"
  end
end

def str_to_level(log_level_str)
  case log_level_str.downcase
  when "trace" then LEVEL_TRACE
  when "debug" then LEVEL_DEBUG
  when "info"  then LEVEL_INFO
  when "warn"  then LEVEL_WARN
  when "error" then LEVEL_ERROR
  when "fatal" then LEVEL_FATAL
  else raise "Unknown log level: level = #{log_level_str}"
  end
end