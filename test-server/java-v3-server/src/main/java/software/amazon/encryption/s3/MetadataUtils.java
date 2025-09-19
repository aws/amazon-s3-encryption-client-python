package software.amazon.encryption.s3;

import software.amazon.encryption.s3.model.GenericServerError;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MetadataUtils {

  /**
   * Annoyingly, Smithy doesn't provide an interface for map types
   * in HTTP headers, so we have to do the serde ourselves
   */
  public static List<String> metadataMapToList(Map<String, String> md) {
    List<String> mdAsList = new ArrayList<>(md.size());
    for (Map.Entry<String, String> keyValue : md.entrySet()) {
      mdAsList.add("[" + keyValue.getKey() + "]:[" + keyValue.getValue() + "]");
    }
    return mdAsList;
  }

  public static Map<String, String> metadataListToMap(List<String> mdList) {
    Map<String, String> md = new HashMap<>();
    for (String entry : mdList) {
      // Split on "]:[" to separate key and value
      String[] parts = entry.split("]:\\[");
      if (parts.length == 2) {
        // Remove remaining brackets from start and end
        String key = parts[0].substring(1);
        String value = parts[1].substring(0, parts[1].length() - 1);
        md.put(key, value);
      } else {
        throw GenericServerError.builder()
          .message("Malformed metadata list entry: " + entry)
          .build();
      }
    }
    return md;
  }

}
