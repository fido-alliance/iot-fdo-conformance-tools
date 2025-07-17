package to2

import (
	"fmt"
	"log"
	"net/http"

	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
	"github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom"
	listenertestsdeps "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom/listener"
)

const MTU_BYTES = 1500

func (h *DoTo2) DeviceServiceInfo68(w http.ResponseWriter, r *http.Request) {
	log.Println("DeviceServiceInfo68: Receiving...")

	var currentCmd fdoshared.FdoCmd = fdoshared.TO2_68_DEVICE_SERVICE_INFO
	var fdoTestId testcom.FDOTestID = testcom.NULL_TEST

	session, sessionId, authorizationHeader, bodyBytes, testcomListener, err := h.receiveAndDecrypt(w, r, currentCmd)
	if err != nil {
		return
	}

	if testcomListener != nil && !testcomListener.To2.CheckCmdTestingIsCompleted(currentCmd) {
		var isLastTestFailed bool

		if !testcomListener.To2.CheckExpectedCmd(currentCmd) && testcomListener.To2.GetLastTestID() != testcom.FIDO_LISTENER_POSITIVE {
			testcomListener.To2.PushFail("Expected the device to fail, but it didn't")
			isLastTestFailed = true
		} else if testcomListener.To2.CheckExpectedCmd(currentCmd) && testcomListener.To2.GetLastTestID() != testcom.FIDO_LISTENER_POSITIVE && session.PrevCMD == fdoshared.TO2_69_OWNER_SERVICE_INFO {
			testcomListener.To2.PushFail("Expected the device to fail, but it didn't")
			isLastTestFailed = true
		} else if testcomListener.To2.CurrentTestIndex != 0 {
			testcomListener.To2.PushSuccess()
		}

		if !testcomListener.To2.CheckCmdTestingIsCompleted(currentCmd) {
			fdoTestId = testcomListener.To2.GetNextTestID()
		}

		err := h.listenerDB.Update(testcomListener)
		if err != nil {
			listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Conformance module failed to save result! "+err.Error(), http.StatusBadRequest, testcomListener, fdoshared.To2)
			return
		}

		if isLastTestFailed {
			return
		}
	}

	if session.PrevCMD != fdoshared.TO2_67_OWNER_SERVICE_INFO_READY && session.PrevCMD != fdoshared.TO2_69_OWNER_SERVICE_INFO {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, fmt.Sprintf("Expected previous CMD to be %d or %d. Got %d", fdoshared.TO2_67_OWNER_SERVICE_INFO_READY, fdoshared.TO2_69_OWNER_SERVICE_INFO, session.PrevCMD), http.StatusUnauthorized, testcomListener, fdoshared.To2)
		return
	}

	// ----- MAIN BODY ----- //

	if session.OwnerSIMsFinishedSending {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INVALID_MESSAGE_ERROR, currentCmd, "DeviceServiceInfo68: Owner has already finished sending its service info", http.StatusBadRequest, testcomListener, fdoshared.To2)
		return
	}

	var deviceServiceInfo fdoshared.DeviceServiceInfo68
	err = fdoshared.CborCust.Unmarshal(bodyBytes, &deviceServiceInfo)
	if err != nil {
		listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "DeviceServiceInfo68: Error encrypting..."+err.Error(), http.StatusBadRequest, testcomListener, fdoshared.To2)
		return
	}

	ownerServiceInfo := fdoshared.OwnerServiceInfo69{}

	if deviceServiceInfo.IsMoreServiceInfo {
		// Device keeps sending more service info
		ownerServiceInfo.IsDone = false
		ownerServiceInfo.IsMoreServiceInfo = false

		session.DeviceSIMs = append(session.DeviceSIMs, deviceServiceInfo.ServiceInfo...)
	} else {
		// Owner is now sending its service info
		if session.OwnerSIMsSendCounter == 0 {
			resultSims, err := ValidateDeviceSIMs(session.Guid, session.DeviceSIMs)
			if err != nil {
				log.Println("DeviceServiceInfo68: Error validating device sims: " + err.Error())
				fdoshared.RespondFDOError(w, r, fdoshared.MESSAGE_BODY_ERROR, currentCmd, "DeviceServiceInfo68: Error validating device sims: "+err.Error(), http.StatusInternalServerError)
				return
			}

			log.Println("DeviceServiceInfo68: Validated device sims: ", *resultSims.SIM_DEVMOD_ARCH, *resultSims.SIM_DEVMOD_DEVICE, resultSims.SIM_DEVMOD_OS)
		}

		if int(session.OwnerSIMsSendCounter+1) >= len(session.OwnerSIMs) {
			ownerServiceInfo.IsDone = true
			ownerServiceInfo.IsMoreServiceInfo = false

			// Updating session
			session.OwnerSIMsFinishedSending = true
		} else {
			ownerServiceInfo.IsDone = false
			ownerServiceInfo.IsMoreServiceInfo = true
		}

		ownerServiceInfo.ServiceInfo = []fdoshared.ServiceInfoKV{}

		if int(session.OwnerSIMsSendCounter)+1 <= len(session.OwnerSIMs) {
			ownerServiceInfo.ServiceInfo = append(ownerServiceInfo.ServiceInfo, session.OwnerSIMs[session.OwnerSIMsSendCounter])
		}

		session.OwnerSIMsSendCounter = session.OwnerSIMsSendCounter + 1
	}

	ownerServiceInfoBytes, _ := fdoshared.CborCust.Marshal(ownerServiceInfo)

	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_68_BAD_ENCODING {
		ownerServiceInfoBytes = fdoshared.Conf_RandomCborBufferFuzzing(ownerServiceInfoBytes)
	}

	// ----- MAIN BODY ENDS ----- //
	ownerServiceInfoEncBytes, err := fdoshared.AddEncryptionWrapping(ownerServiceInfoBytes, session.SessionKey, session.CipherSuiteName)
	if err != nil {
		log.Println("DeviceServiceInfo68: Error encrypting..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Internal server error!", http.StatusInternalServerError)
		return
	}

	if fdoTestId == testcom.FIDO_LISTENER_DEVICE_68_BAD_ENC_WRAPPING {
		ownerServiceInfoEncBytes, err = fdoshared.Conf_Fuzz_AddWrapping(ownerServiceInfoEncBytes, session.SessionKey, session.CipherSuiteName)
		if err != nil {
			log.Println("DeviceServiceInfo68: Error fuzzing encryption..." + err.Error())
			fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Internal server error!", http.StatusInternalServerError)
			return
		}
	}

	session.PrevCMD = fdoshared.TO2_69_OWNER_SERVICE_INFO

	err = h.session.UpdateSessionEntry(sessionId, *session)
	if err != nil {
		log.Println("DeviceServiceInfo68: Error saving session..." + err.Error())
		fdoshared.RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Internal server error!", http.StatusInternalServerError)
		return
	}

	if fdoTestId == testcom.FIDO_LISTENER_POSITIVE && testcomListener.To2.CheckExpectedCmd(currentCmd) {
		testcomListener.To2.PushSuccess()
		testcomListener.To2.CompleteCmdAndSetNext(fdoshared.TO2_70_DONE)
		err := h.listenerDB.Update(testcomListener)
		if err != nil {
			listenertestsdeps.Conf_RespondFDOError(w, r, fdoshared.INTERNAL_SERVER_ERROR, currentCmd, "Conformance module failed to save result!", http.StatusBadRequest, testcomListener, fdoshared.To2)
			return
		}
	}

	w.Header().Set("Authorization", authorizationHeader)
	w.Header().Set("Content-Type", fdoshared.CONTENT_TYPE_CBOR)
	w.Header().Set("Message-Type", fdoshared.TO2_69_OWNER_SERVICE_INFO.ToString())
	w.WriteHeader(http.StatusOK)
	w.Write(ownerServiceInfoEncBytes)
}
