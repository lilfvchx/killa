cd Payload_Type/killa/killa/agent_code
mkdir -p temp_pkg
cp pkg/commands/*.go temp_pkg/
cd temp_pkg
rm netlocalgroup.go netloggedon.go netsession.go netshares.go
GOOS=windows go build -o /dev/null . || echo "Build error in temp pkg"
