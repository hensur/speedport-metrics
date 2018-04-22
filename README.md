# Speedport Entry 2 metrics

This tool can fetch the dsl metrics from a Speedport Entry 2. These metrics are then returned as a python dictionary.

## About

This tools is especially useful if the speedport is used as a modem only. In this mode it is only possible to connect using the second LAN Port and the modem IP Address `169.254.2.1`.
However, the javascrip redirects everything to a simple status page which only shows the dsl sync.

It is still possible to login, the login page just gets redirected to the modem page.

This tool logs in to the router and the fetches the dsl info page. The parsed page content is returned as a python dict.

The login procedure is explained in the code comments :).

## TODO

- Write the data to influxd
- Provide a metrics endpoint for prometheus