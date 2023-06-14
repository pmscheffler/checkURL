### checkURL

This quick Python script will allow you to test a URL (the 'target') to see if it will generate a Violation on your BIG-IP.

The script will hit the URL (you can add headers and choose a method plus include payload data) and then look at the response.  If the response is a standard blocking page, it'll check with the BIG-IP for the associated Violations record.

