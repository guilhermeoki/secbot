#!/bin/bash -x
cd
rm -rf $GOPATH/src/github.com/pagarme/secbot
go get github.com/pagarme/secbot
go build $GOPATH/src/github.com/pagarme/secbot/run/main.go
sudo systemctl stop secbot
if [ ! -d "$SECBOT_PATH/secbot_backup/" ]; then
	mkdir $SECBOT_PATH/secbot_backup/
fi
cp $SECBOT_PATH/secbot $SECBOT_PATH/secbot_backup/secbot_bkp_`date +%H:%M:%S-%d:%m:%Y`
cp $SECBOT_PATH/secbot.db $SECBOT_PATH/secbot_backup/db_secbot_bkp_`date +%H:%M:%S-%d:%m:%Y`.db 
mv main $SECBOT_PATH/secbot
sudo systemctl start secbot
