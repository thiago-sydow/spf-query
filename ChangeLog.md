### 0.1.2 / 2015-07-07

#### parser

* Convert all chars and literals to Strings.
* Properly transform macro_strings that contain a single literal into a String.

### 0.1.1 / 2015-07-06

* Raise {SPF::Query::SenderIDFound} from {SPF::Query::Record.parse} if
  [Sender ID](http://www.openspf.org/SPF_vs_Sender_ID) is detected.

### 0.1.0 / 2015-07-01

* Initial release:
  * Queries and parses SPF records.
  * Supports querying both TXT and SPF records.

