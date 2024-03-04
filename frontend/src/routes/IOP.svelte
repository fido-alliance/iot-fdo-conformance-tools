<script lang="ts">
    import {iopRegisterVoucher} from '../lib/DeviceTest.api'

    let fileName = ""
    let fileinput
    const readAndDecodeFile = async(e) => {
        return new Promise((resolve, reject) => {
            let selectedImageReference = e.target.files[0];

            if (e.target.files.length > 0) {
                fileName = `File selected: ${e.target.files[0].name}`
            } else {
                return reject("No file selected")
            }

            let reader = new FileReader();
            reader.readAsDataURL(selectedImageReference);
            reader.onload = (e) => {
                let resultSplit = e.target.result.split(/^.*;base64,/);

                resolve(atob(resultSplit[1]))
            };

            reader.onerror = (e) => {
                reject("Error reading file")
            }
        })
    }

    let newDeviceFileString 
    const readFile = async(e) => {
        newIopErrorMessage = ""

        let fileString = await readAndDecodeFile(e)
        newDeviceFileString = fileString
    }

    let newIopErrorMessage = ""
    const handleAddNewVoucher = async(e) => {
        e.preventDefault()

        newIopErrorMessage = ""
        
        // DecodeB64 pem file
        try {    
            let logs = await iopRegisterVoucher(newDeviceFileString)

            for(let log of logs) {
                newIopErrorMessage += log + "\n"
            }
        } catch(e) {
            newIopErrorMessage = "Error submitting voucher. " + e
            return
        }

        newIopErrorMessage = "Success"
    }
</script>

<section id="first" class="main special">
    <header class="major">
        <h2><b>FDO Interop Tools</b></h2>
    </header>

    <div class="row gtr-uniform">
        <div class="col-4 col-12-xsmall">
            <div class="row">
                <div class="col-12 col-12-xsmall">
                    <h3>Rendezvous Service</h3>
                    <span class="icon solid major style3 fa fa-database"></span>
                </div>

                <div class="col-12 col-12-xsmall maximise">
                    <p>HTTPS/TLS</p>
                    <code>https://rv.fdo.tools:443</code>
                    <code>https://104.21.0.92:443</code>
                </div>
                <div class="col-12 col-12-xsmall maximise">
                    <p>HTTP ONLY</p>
                    <code>http://http.rv.fdo.tools:80</code>
                    <code>http://165.227.240.155:80</code>
                    <code>https://172.67.150.203:443</code>
                </div>

                <div class="col-12 col-12-xsmall maximise">
                    <b><p>Additional Resource</p></b>
                    <a href="https://github.com/fido-alliance/conformance-test-tools-resources/blob/main/docs/FDO">FIDO Alliance FDO Resources</a>
                </div>
            </div>
        </div>
        <div class="col-8 col-12-xsmall">
            <div class="row">
                <div class="col-12 col-12-xsmall">
                    <h3>Device Onboarding Service</h3>
                    <span class="icon solid major style3 fa fa-cogs"></span>
                </div>

                <div class="col-12 col-12-xsmall maximise">
                    <div class="row">
                        <div class="col-8 col-12-xsmall">
                            <input type="file" id="file" name="demo-name" accept="*" on:change={(e)=>readFile(e)} bind:this={fileinput} style="display: none" />
                            <label for="file" class="button maximise primary">Choose File</label>
                        </div>
                        <div class="col-4 col-12-xsmall">
                            <a href="#" class="button maximise primary exec" on:click={handleAddNewVoucher}>Submit</a>
                        </div>
                        <div class="col-12 col-12-xsmall">
                            <p>{fileName}</p>
                        </div>
                    </div>
                    <div class="row">
                        <div class="col-12 col-12-xsmall">
                            <p>{newIopErrorMessage}</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</section>