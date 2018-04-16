"""
Support for Nest devices.

For more details about this component, please refer to the documentation at
https://home-assistant.io/components/nest/
"""
import logging
import uuid
import socket

import voluptuous as vol

from homeassistant import config_entries, data_entry_flow
from homeassistant.core import callback
from homeassistant.loader import bind_hass
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers import discovery
from homeassistant.const import (
    CONF_STRUCTURE, CONF_FILENAME, CONF_BINARY_SENSORS, CONF_SENSORS,
    CONF_MONITORED_CONDITIONS)

REQUIREMENTS = ['python-nest==3.7.0']

_CONFIGURING = {}
_LOGGER = logging.getLogger(__name__)

DOMAIN = 'nest'

DATA_NEST = 'nest'
DATA_NEST_FLOW = 'nest_config_flow'

NEST_CONFIG_FILE = 'nest.conf'
CONF_CLIENT_ID = 'client_id'
CONF_CLIENT_SECRET = 'client_secret'

ATTR_HOME_MODE = 'home_mode'
ATTR_STRUCTURE = 'structure'

SENSOR_SCHEMA = vol.Schema({
    vol.Optional(CONF_MONITORED_CONDITIONS): vol.All(cv.ensure_list)
})

AWAY_SCHEMA = vol.Schema({
    vol.Required(ATTR_HOME_MODE): cv.string,
    vol.Optional(ATTR_STRUCTURE): vol.All(cv.ensure_list, cv.string)
})

CONFIG_SCHEMA = vol.Schema({
    DOMAIN: vol.Schema({
        vol.Required(CONF_CLIENT_ID): cv.string,
        vol.Required(CONF_CLIENT_SECRET): cv.string,
        vol.Optional(CONF_STRUCTURE): vol.All(cv.ensure_list, cv.string),
        vol.Optional(CONF_SENSORS): SENSOR_SCHEMA,
        vol.Optional(CONF_BINARY_SENSORS): SENSOR_SCHEMA
    })
}, extra=vol.ALLOW_EXTRA)


def request_configuration(nest, hass, config):
    """Request configuration steps from the user."""
    configurator = hass.components.configurator
    if 'nest' in _CONFIGURING:
        _LOGGER.debug("configurator failed")
        configurator.notify_errors(
            _CONFIGURING['nest'], "Failed to configure, please try again.")
        return

    def nest_configuration_callback(data):
        """Run when the configuration callback is called."""
        _LOGGER.debug("configurator callback")
        pin = data.get('pin')
        setup_nest(hass, nest, config, pin=pin)

    _CONFIGURING['nest'] = configurator.request_config(
        "Nest", nest_configuration_callback,
        description=('To configure Nest, click Request Authorization below, '
                     'log into your Nest account, '
                     'and then enter the resulting PIN'),
        link_name='Request Authorization',
        link_url=nest.authorize_url,
        submit_caption="Confirm",
        fields=[{'id': 'pin', 'name': 'Enter the PIN', 'type': ''}]
    )


def setup_nest(hass, nest, config, pin=None):
    """Set up the Nest devices."""
    if pin is not None:
        _LOGGER.debug("pin acquired, requesting access token")
        nest.request_token(pin)

    if nest.access_token is None:
        _LOGGER.debug("no access_token, requesting configuration")
        request_configuration(nest, hass, config)
        return

    if 'nest' in _CONFIGURING:
        _LOGGER.debug("configuration done")
        configurator = hass.components.configurator
        configurator.request_done(_CONFIGURING.pop('nest'))

    _LOGGER.debug("proceeding with setup")
    conf = config[DOMAIN]
    hass.data[DATA_NEST] = NestDevice(hass, conf, nest)

    _LOGGER.debug("proceeding with discovery")
    discovery.load_platform(hass, 'climate', DOMAIN, {}, config)
    discovery.load_platform(hass, 'camera', DOMAIN, {}, config)

    sensor_config = conf.get(CONF_SENSORS, {})
    discovery.load_platform(hass, 'sensor', DOMAIN, sensor_config, config)

    binary_sensor_config = conf.get(CONF_BINARY_SENSORS, {})
    discovery.load_platform(hass, 'binary_sensor', DOMAIN,
                            binary_sensor_config, config)

    _LOGGER.debug("setup done")

    return True


def setup(hass, config):
    """Set up the Nest thermostat component."""
    import nest

    # When we are doing config entries.
    if DOMAIN not in config:
        return True

    conf = config[DOMAIN]
    client_id = conf[CONF_CLIENT_ID]
    client_secret = conf[CONF_CLIENT_SECRET]
    filename = config.get(CONF_FILENAME, NEST_CONFIG_FILE)

    access_token_cache_file = hass.config.path(filename)

    nest = nest.Nest(
        access_token_cache_file=access_token_cache_file,
        client_id=client_id, client_secret=client_secret)
    setup_nest(hass, nest, config)

    def set_mode(service):
        """Set the home/away mode for a Nest structure."""
        if ATTR_STRUCTURE in service.data:
            structures = service.data[ATTR_STRUCTURE]
        else:
            structures = hass.data[DATA_NEST].local_structure

        for structure in nest.structures:
            if structure.name in structures:
                _LOGGER.info("Setting mode for %s", structure.name)
                structure.away = service.data[ATTR_HOME_MODE]
            else:
                _LOGGER.error("Invalid structure %s",
                              service.data[ATTR_STRUCTURE])

    hass.services.register(
        DOMAIN, 'set_mode', set_mode, schema=AWAY_SCHEMA)

    return True


class NestDevice(object):
    """Structure Nest functions for hass."""

    def __init__(self, hass, conf, nest):
        """Init Nest Devices."""
        self.hass = hass
        self.nest = nest

        if CONF_STRUCTURE not in conf:
            self.local_structure = [s.name for s in nest.structures]
        else:
            self.local_structure = conf[CONF_STRUCTURE]
        _LOGGER.debug("Structures to include: %s", self.local_structure)

    def thermostats(self):
        """Generate a list of thermostats and their location."""
        try:
            for structure in self.nest.structures:
                if structure.name in self.local_structure:
                    for device in structure.thermostats:
                        yield (structure, device)
                else:
                    _LOGGER.debug("Ignoring structure %s, not in %s",
                                  structure.name, self.local_structure)
        except socket.error:
            _LOGGER.error(
                "Connection error logging into the nest web service.")

    def smoke_co_alarms(self):
        """Generate a list of smoke co alarms."""
        try:
            for structure in self.nest.structures:
                if structure.name in self.local_structure:
                    for device in structure.smoke_co_alarms:
                        yield(structure, device)
                else:
                    _LOGGER.info("Ignoring structure %s, not in %s",
                                 structure.name, self.local_structure)
        except socket.error:
            _LOGGER.error(
                "Connection error logging into the nest web service.")

    def cameras(self):
        """Generate a list of cameras."""
        try:
            for structure in self.nest.structures:
                if structure.name in self.local_structure:
                    for device in structure.cameras:
                        yield(structure, device)
                else:
                    _LOGGER.info("Ignoring structure %s, not in %s",
                                 structure.name, self.local_structure)
        except socket.error:
            _LOGGER.error(
                "Connection error logging into the nest web service.")


@bind_hass
def async_register_flow_handler(hass, name, generate_oauth_auth_url, use_pin):
    """Register an auth flow for the config entry flow."""
    flows = hass.data.get(DATA_NEST_FLOW)
    if flows is None:
        flows = hass.data[DATA_NEST_FLOW] = {}
    handler_id = uuid.uuid4().hex
    data = {
        'name': name,
        'generate_oauth_auth_url': generate_oauth_auth_url,
        'use_pin': use_pin,
    }
    flows[handler_id] = data

    @callback
    def async_unregister_handler():
        """Removes the handler."""
        flows.pop(handler_id, None)

    return async_unregister_handler


@config_entries.HANDLERS.register(DOMAIN)
class NestFlowHandler(data_entry_flow.FlowHandler):
    """Handle a Nest config flow."""

    VERSION = 1

    def __init__(self):
        """Initialize Nest config flow."""
        self._flow_handler = None

    async def async_step_init(self, user_input=None):
        """Handle a flow start."""
        flows = self.hass.data.get(DATA_NEST_FLOW, [])

        if not flows:
            return self.async_abort(
                reason='no_flow'
            )
        elif len(flows) == 1:
            self._flow_handler = list(flows.keys())[0]
            return await self.async_step_flow()

        # Handle if we have multiple flows we show a picker.

    async def async_step_flow(self, user_input=None):
        """Handle the flow authentication."""
        handler = self.hass.data[DATA_NEST_FLOW][self._flow_handler]

        if user_input:
            return self.async_create_entry(
                title='Nest temp',
                data=user_input,
            )

        url = await handler['generate_oauth_auth_url'](self.flow_id)

        return self.async_external_step(
            step_id='flow',
            url=url,
        )
