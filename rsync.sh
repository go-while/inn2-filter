rsync -va --progress etc/news/filter/filter_nnrpd.pl root@reader-nyc.newsdeef.eu:/etc/news/filter/filter_nnrpd.pl
rsync -va --progress news/ root@reader-nyc.newsdeef.eu:/news/
ssh root@reader-nyc.newsdeef.eu "chown news:news -R /news /etc/news/filter; chmod 700 /news; ctlinnd reload all filter"

