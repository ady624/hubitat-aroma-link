/**
 * -----------------------
 * ------ SMART APP ------
 * -----------------------
 *
 *  Aroma-Link Diffuser Integration
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

import groovy.transform.Field
import java.security.MessageDigest
import com.hubitat.app.DeviceWrapper

@Field BASE_URI = "https://www.aroma-link.com"
@Field PATH_LOGIN = "/v2/app/token/"
@Field PATH_LIST = "/v1/app/device/listAll/"
@Field PATH_DEVICE = "/v1/app/device/"
@Field PATH_CONTROL = "/v1/app/data/switch"

String appVersion() { return "0.1.0" }
String appModified() { return "2024-02-18"}
String appAuthor() { return "Adrian Caramaliu" }
String gitBranch() { return "ady624" }
String getAppImg(imgName) 	{ return "https://raw.githubusercontent.com/${gitBranch()}/hubitat-aroma-link/master/icons/$imgName" }

definition(
	name: "Aroma-Link Diffuser Integration",
	namespace: "ady624",
	author: "Adrian Caramaliu",
	description: "Integrate Aroma-Link with Hubitat",
	category: "Integrations",
	importUrl: "https://github.com/ady624/hubitat-aroma-link.groovy",
	iconUrl:   "",
	iconX2Url: "",
	iconX3Url: ""
)

preferences {
	page(name: "pgMain", title: "Aroma-Link Integration")
    page(name: "pgLogin", title: "Aroma-Link Login")
    page(name: "pgLoginFailure", title: "Aroma-Link Integration")
    page(name: "pgUninstall", title: "Uninstall")
}

def appInfoSect(sect=true)	{
	def str = ""
	str += "${app?.name} (v${appVersion()})"
	str += "\nAuthor: ${appAuthor()}"
	section() { paragraph str, image: getAppImg("aroma-link@2x.png") }
}

def pgMain() {

    if (state.previousVersion == null){
        state.previousVersion = 0;
    }

    //Brand new install (need to grab version info)
    if (!state.latestVersion){
        state.currentVersion = [:]
        state.currentVersion['SmartApp'] = appVersion()
    }
    //Version updated
    else{
        state.previousVersion = appVersion()
    }

    state.lastPage = "pgMain"

    //If fresh install, go straight to login page
    if (!settings.username){
        return pgLogin()
    }
    
    dynamicPage(name: "pgMain", nextPage: "", uninstall: false, install: true) {
        appInfoSect()      
        section("Aroma-Link Account"){
            href "pgLogin", title: settings.username, description: "Tap to modify", params: [nextPageName: "pgMain"]
        }
        section("Connected diffusers:"){
            state.diffusers.each { user -> 
                paragraph "• ${user.value.firstName} ${user.value.lastName}"
            }
            
        }
        section("") {
            paragraph "Tap below to completely uninstall this SmartApp and child devices"
            href(name: "", title: "",  description: "Tap to Uninstall", required: false, page: "pgUninstall")
        }
    }
}

/* Preferences */
def pgLogin(params) {
    state.installMsg = ""
    def showUninstall = username != null && password != null
	return dynamicPage(name: "pgLogin", title: "Connect to Freestyle Libre LinkUp", nextPage:"pgLoginFailure", uninstall:false, install: false, submitOnChange: true) {
		section("Credentials"){
			input("username", "text", title: "Username", description: "Aroma-Link username")
			input("password", "password", title: "Password", description: "Aroma-link password")
		}
	}
}

def pgLoginFailure(){
    if (doLogin()) {
        refreshDiffusers()
        return pgMain()
    }
    else{
    	return dynamicPage(name: "pgLoginFailure", title: "Login Error", install:false, uninstall:false) {
            section(""){
                paragraph "The username or password you entered is incorrect. Go back and try again. "
			}
		}
    }
}

def pgUninstall() {
    def msg = ""
    childDevices.each {
		try{
			deleteChildDevice(it.deviceNetworkId, true)
            msg = "Devices have been removed. Tap remove to complete the process."

		}
		catch (e) {
			log.error "Error deleting ${it.deviceNetworkId}: ${e}"
            msg = "There was a problem removing your device(s). Check the IDE logs for details."
		}
	}

    return dynamicPage(name: "pgUninstall",  title: "Uninstall", install:false, uninstall:true) {
        section("Uninstall"){
			paragraph msg
		}
    }
}



def versionCompare(deviceName){
    if (!state.currentVersion || !state.latestVersion || state.latestVersion == [:]){
        return 'latest'
    }
    if (state.currentVersion[deviceName] == state.latestVersion[deviceName]){
    	return 'latest'
    }
    else{
   		return "${state.latestVersion[deviceName]} available"
    }
}

/* Initialization */
def installed() {
    initialize()
}

def updated() {
    initialize()
}

/* Version Checking */

def updateVersionInfo(){
}

def uninstall(){
    getChildDevices().each {
		try{
			deleteChildDevice(it.deviceNetworkId, true)
		}
		catch (e) {
            log.error "Error deleting ${it.deviceNetworkId}: ${e}"
		}
	}
}

def uninstalled() {
    log.info "Freestyle Libre removal complete."
}


def initialize() {
    unschedule()
    runEvery5Minutes("refreshDiffusers")
}

String md5(String s){
    MessageDigest.getInstance("MD5").digest(s.bytes).encodeHex().toString()
}

def String epochToDate( Number Epoch ){
    def date = use( groovy.time.TimeCategory ) {
          new Date( 0 ) + Epoch.seconds
    }
    return date
}
                        
private login() {
	if (!state.session || (now() > state.session.expiration)) {
    	log.warn "Token has expired. Logging in again."
        doLogin()
    }
    else{
    	return true;
    }
}

private doLogin() {
    state.session = [ authToken: null, expiration: 0 ]
    return doUserNameAuth()
}

/* API Methods */
private getApiHeaders() {
	headers = [
        "Accept-Encoding": "gzip",
        "User-Agent": "okhttp/4.5.0",
        "version": "406"
        ]
    if (state.session?.authToken) {
        headers["access_token"] = state.session.authToken
    }
    return headers
}

def doUserNameAuth() {
    def result = true
    log.info "Performing login..."
    try {
        httpPost([ 
            uri: BASE_URI, 
            path: PATH_LOGIN,
            headers: getApiHeaders(),
            query: [
                "userName": settings.username,
                "password": md5(settings.password)
            ],
            requestContentType: "application/x-www-form-urlencoded"
        ]) { resp ->
			if ((resp.status == 200) && resp.data && (resp.data.code == 200)) {
                state.session = [
                    authToken: resp.data.data.accessToken,
                    expiration: now() + resp.data.data.accessTokenValidity as long,
                    userId: resp.data.data.id
                ]
                log.info "Login successful"
                result = true                
            }
            else {
                log.error "Error logging in: ${resp.status}"
                result = false
            }
        }
    }
    catch (e) {
        log.error "Error logging in: ${e}"
        return false
    }
    return result
}

def refreshDiffusers(){
	state.currentVersion = [:]
    state.currentVersion['SmartApp'] = appVersion()
    state.diffusers = [:]
    deviceIds = getChildDevices()*.deviceNetworkId
    if (login()) {
        httpGet([ 
            uri: BASE_URI, 
            path: PATH_LIST + state.session.userId.toString(),
            headers: getApiHeaders()
        ]) { resp ->
            if ((resp.status == 200) && resp.data && (resp.data.code == 200)) {
                resp.data.data.each { group ->
                    if (group.type == "group") {
                        group.children.each { device ->
                            if (device.type == "device") {
                                diffuser = [
                                    "id": device.id,
                                    "name": device.text,
                                    "groupId": group.id,
                                    "groupName": group.text,
                                    "deviceNo": device.deviceNo,
                                    "deviceType": device.deviceType,
                                    "hasFan": device.hasFan,
                                    "hasLamp": device.hasLamp,
                                    "hasPump": device.hasPump,
                                    "hasWeight": device.hasWeight,
                                    "hasBattery": device.hasBattery,
                                    "battery": device.battery,
                                    "status": device.isError ? (device.errorMsg ?: "error") : "normal",
                                    "isFragranceLevel": device.isFragranceLevel,
                                    "lowRemainOij": device.lowRemainOij,
                                    "remainOil": device.remainOil,
                                    "netType": device.netType,
                                    "onlineStatus": device.onlineStatus                                    
                                    ]
                                diffuserId = "aroma-link-${diffuser.id}"
                                state.diffusers[diffuserId] = diffuser
                                device = getChildDevice(diffuserId)
                                if (device) {
                                    device.update(diffuser)
                                } else {
                                    log.info "Adding new device for diffuser ${diffuser.name}"
                                    dw = addChildDevice("ady624", "Aroma-Link Diffuser", diffuserId, ["name": diffuser.name]).update(diffuser)
                                    dw.sendEvent([name: "networkStatus", value: "online"])

                                }
                                deviceIds -= diffuserId
                            }
                        }
                    }
                }
            }
            deviceIds.each { deviceId -> 
                log.warn "Deleting device ${deviceId}"
                deleteChildDevice(deviceId)
            }
        }
    }
}

private void sendDeviceCommand(DeviceWrapper dw, String command, int value) {
    long deviceId = dw.getDeviceNetworkId().minus("aroma-link-") as long
    if (login()) {
        httpPost([ 
            uri: BASE_URI, 
            path: PATH_CONTROL,
            headers: getApiHeaders(),
            body: [
                "deviceId": deviceId,
                "userId": state.session.userId,
                "${command}": value
            ],
            requestContentType: "application/x-www-form-urlencoded"
        ]) { resp ->
            log.info("Sending command deviceId=${deviceId}, command=${command}, value=${value}, userId=${state.session.userId}")
            if (resp.status != 200 || resp.data.code != 200) {
                log.warn("Device ${deviceId} appears offline")
            }
            dw.sendEvent([name: "networkStatus", value: resp.status == 200 || resp.data.code != 200 ? "online" : "offline"])
        }
    } else {
        dw.sendEvent([name: "networkStatus", value: "offline"])
    }
}

public void componentRefresh(DeviceWrapper dw) {
    refreshDiffusers()
}

public void componentOn(DeviceWrapper dw) {  
    sendDeviceCommand(dw, "onOff", 1)
}

public void componentOff(DeviceWrapper dw) {
    sendDeviceCommand(dw, "onOff", 0)   
}

public void componentSetSpeed(DeviceWrapper dw, speed) {
    sendDeviceCommand(dw, "fan", speed == "on" ? 1 : 0)
}
