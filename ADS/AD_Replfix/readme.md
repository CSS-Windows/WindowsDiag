# REPLFIX
ReplFix - Replica Consistency Tool, Version 1.1 (for Windws Server 2016 and later)

### Details
ReplFix version 1.1 detects and corrects lingering objects inconsistencies between two Domain Controllers (DC).

In a very limited way, ReplFix 1.1 detects and corrects lingering values inconsistencies between a quiesced GC hosting a writable copy and a quiesced GC hosting a read-only copy of a domain partition.
An ldifde script is created that corrects the differences but since replication latency is not taken into account, the script must be reviewed for correctness.

The commandline syntax is:
  replfix [-?]
    -? - help and examples

### Important "General Data Protection Regulation and Legal" Notes:
REPLFIX is provided as it is and neither Microsoft nor the author have any legal responsibility over it.