# Utility class for handling metadata serialization/deserialization
# Matches the format used by Java and Python servers: [key]:[value],[key2]:[value2]
class MetadataUtils
  # Convert metadata string to hash
  # Input: "[user-defined-enc-ctx-key]:[user-defined-enc-ctx-value],[user-defined-enc-ctx-key-2]:[user-defined-enc-ctx-value-2]"
  # Output: {"user-defined-enc-ctx-key" => "user-defined-enc-ctx-value", "user-defined-enc-ctx-key-2" => "user-defined-enc-ctx-value-2"}
  def self.string_to_map(metadata_string)
    return {} if metadata_string.nil? || metadata_string.empty?

    metadata = {}
    entries = metadata_string.split(',')
    
    entries.each do |entry|
      # Split on "]:[" to separate key and value
      parts = entry.split(']:[')
      if parts.length == 2
        # Remove remaining brackets from start and end
        key = parts[0].delete_prefix("[")  # Remove first character '['
        value = parts[1].delete_suffix("]")  # Remove last character ']'
        metadata[key] = value
      else
        raise "Malformed metadata list entry: #{entry}"
      end
    end

    metadata
  end

  # Convert hash to metadata string
  # Input: {"user-defined-enc-ctx-key" => "user-defined-enc-ctx-value", "user-defined-enc-ctx-key-2" => "user-defined-enc-ctx-value-2"}
  # Output: "[user-defined-enc-ctx-key]:[user-defined-enc-ctx-value],[user-defined-enc-ctx-key-2]:[user-defined-enc-ctx-value-2]"
  def self.map_to_string(metadata_hash)
    return '' if metadata_hash.nil? || metadata_hash.empty?

    entries = metadata_hash.map do |key, value|
      "[#{key}]:[#{value}]"
    end
    
    entries.join(',')
  end

  # Convert metadata hash to array format (for JSON responses)
  def self.map_to_array(metadata_hash)
    return [] if metadata_hash.nil? || metadata_hash.empty?

    metadata_hash.map do |key, value|
      "[#{key}]:[#{value}]"
    end
  end
end
