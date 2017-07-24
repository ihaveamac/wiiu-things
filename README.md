# Wii U things
Things I made (or found?) when playing around with the Wii U

* `wiiu_cdndownload.py` - download titles from Nintendo CDN, including cetk (ticket) for system titles/game updates/etc
* `wiiu_decrypt.py` - decrypt titles from Nintendo CDN; requires Wii U Common Key, plus given encrypted titlekey if there is no cetk file
* `wiiu_extract.py` - extract contents from titles
  * `--dump-info` - print lots more info
  * `--full-paths` - show full paths in output
  * `--no-extract` - don't extract files, only show info
  * `--all` - show all files, including those with 0x80 bitmask in type (which probably means deleted file). only useful for title updates.
