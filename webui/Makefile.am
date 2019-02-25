


if BUILDUI

webdir=@WEBUI@
web_DATA=funcs.php edit.css index.php mm.js mud-edit.php mud-home.php \
	show-acl-policy.php statics.php style.css

install-data-hook:
	@echo You must now run composer in $(webdir) as follows:
	@echo @COMPOSER@ require mongodb/mongodb
	@echo
	@echo This may not be done as root.

endif
