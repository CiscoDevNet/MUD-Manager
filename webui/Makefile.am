


if BUILDUI

webdir=@WEBUI@
web_DATA=funcs.php edit.css index.php mm.js mud-edit.php mud-home.php \
	show-acl-policy.php statics.php style.css

install-data-hook:
	( cd $(webdir); @COMPOSER@ require mongodb/mongodb )
endif
