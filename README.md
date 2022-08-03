# Wii U things
Things I made (or found?) when playing around with the Wii U

[FST format layout](https://github.com/ihaveamac/wiiu-things/wiki/FST)

* `wiiu_cdndownload.py` - download titles from Nintendo CDN, including cetk (ticket) for system titles/game updates/etc
* `wiiu_decrypt.py` - decrypt titles from Nintendo CDN; requires Wii U Common Key, plus given encrypted titlekey if there is no cetk file
* `wiiu_extract.py` - extract contents from titles
  * `--dump-info` - print lots more info
  * `--full-paths` - show full paths in output
  * `--no-extract` - don't extract files, only show info
  * `--all` - show all files, including those with 0x80 bitmask in type (which probably means deleted file). only useful for title updates.
* `wiiu_no-intro_to_wup.py` - recreate missing .h3 files, ticket and certificate from No-Intro "Nintendo - Wii U (Digital) (CDN)" game
  * If the game requires a ticket file then get it from [here](http://vault.titlekeys.ovh/) and place it as-is into the games directory. The script with rename it from `[TITLE_ID].tik` to `title.tik`. If the game just needs an encrypted title key then get it from the JSON file in [here](http://vault.titlekeys.ovh/) and supply it as the only argument.
