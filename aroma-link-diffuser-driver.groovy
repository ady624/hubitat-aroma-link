/**
 *  Aroma-Link Diffuser
 *
 *  Copyright 2024 Adrian Caramaliu
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License. You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 *  for the specific language governing permissions and limitations under the License.
 *
 */

metadata {
  definition(name: "Aroma-Link Diffuser", namespace: "ady624", author: "Adrian Caramaliu") {
    capability "Refresh"
    capability "Switch"
    capability "FanControl"

    attribute "networkStatus", "enum", ["offline", "online"]
}

  preferences {
  }
}

void installed() {
    sendEvent([name: "supportedFanSpeeds", value: ["on", "off"]])
}

void update(diffuser) {
    updateAttribute("networkStatus", diffuser.onlineStatus ? "online" : "offline")
}

void updateAttribute(String name, value, unit = null) {
    if (device.currentValue(name) as String != value as String) {
        sendEvent(name: name, value: value, unit: unit)
    }
}

public void refresh() {
  parent.componentRefresh(device)
}

public void on() {
    if (device.currentValue("switch") != "on") {
        sendEvent([name: "switch", value: "on"])
    }
    parent.componentOn(device)
}

public void off() {
    if (device.currentValue("switch") != "off") {
        sendEvent([name: "switch", value: "off"])
    }
    parent.componentOff(device)
}

public void setSpeed(speed) {
    speed = speed.toLowerCase() == "off" ? "off" : "on"
    if (device.currentValue("speed") != speed) {
        sendEvent([name: "speed", value: speed])
    }
    parent.componentSetSpeed(device, speed)
}

public void cycleSpeed() {
    setSpeed(device.currentValue("speed") == "on" ? "off" : "on")
}
