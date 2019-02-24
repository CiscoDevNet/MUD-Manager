
if BUILDUI

webdir=@WEBUI@
webuser=@WEBUSER@
composer=@COMPOSER@

web_DATA=funcs.php edit.css index.php mm.js mud-edit.php mud-home.php \
	show-acl-policy.php statics.php style.css

install-data-hook:
	( cd $(webdir);	chown $(webuser) . * ; \
	su -c "$(composer) require mongodb/mongodb" $(webuser) )

endif
