<script>
    import {getDOTsList, removeTestRun, addNewDo, executeDoTests} from '../lib/DOTest.api'
    import {ensureUserIsLoggedIn} from '../lib/User.api'

    ensureUserIsLoggedIn()

    let selectedDOTUuid = ""
    let selectedTestRunUuid = ""

    let testRunMap = {}
    let dotMap = {}


    let errorMsg = ""
    const refreshDotList = async() => {
        try {
            let dotList = await getDOTsList()

            for(let dot of dotList) {
                dotMap[dot.id] = dot

                for(let testRun of dot.to2.runs) {
                    testRunMap[testRun.uuid] = testRun
                }
            }

            
        } catch(err) {
            errorMsg = err; // TypeError: failed to fetch
        }
    }

    const handleSelect = async(e) => {
        

    }

    let doTestExecuteErrorMessage = ""
    const handleDoTestExecuteTo2 = async(e) => {
        e.preventDefault()

        doTestExecuteErrorMessage = "Executing..."
        try {
            await executeDoTests(dotMap[selectedDOTUuid].to2.id)
            doTestExecuteErrorMessage = "Success"
        } catch(e) {
            doTestExecuteErrorMessage = "Error executing DO. " + e
        }

        setTimeout(() => { 
            doTestExecuteErrorMessage = ""
        }, 1250)
    }

    const handleRemoveTestRun = async(id, protocol) => {
        try {
            await removeTestRun(dotMap[selectedDOTUuid].to2.id, id)
        } catch(e) {
            doTestExecuteErrorMessage = "Error removing test run. " + e
        }
    }


/* ----- Handle New DO ----- */
    let newDoErrorMessage = ""
    let newDoUrl = ""
    const handleAddNewDo = async(e) => {
        e.preventDefault()

        newDoErrorMessage = ""

        try {
            new URL(newDoUrl)
            newDoErrorMessage = "Processing..."
            await addNewDo(newDoUrl)
        } catch(e) {
            newDoErrorMessage = "Error adding new DO. " + e
            return
        }

        newDoErrorMessage = "Success"
        setTimeout(() => { 
            newDoUiVisible = false
            newDoErrorMessage = ""
            newDoUrl = ""
        }, 1250)

    }

    let newDoUiVisible = false
    const handleInitiateNewDo = (e) => {
        e.preventDefault()
        newDoUiVisible = true
        newDoErrorMessage = ""
        newDoUrl = ""
    }

    const handleCancelInitiateNewDo = (e) => {
        e.preventDefault()
        newDoUiVisible = false
        newDoErrorMessage = ""
        newDoUrl = ""
    }
/* ----- Handle New Do Ends----- */


    refreshDotList()
    setInterval(() => {
		refreshDotList()
    }, 2000);
</script>

<section id="first" class="main">
    <header>
        <p>{errorMsg}</p>
    </header>

    <div class="row gtr-uniform">
        <div class="col-4 col-12-xsmall">
            <h2>Available DOs for testing</h2>
            <!-- {selectedRVT}
            {selectedTestRunUuid} -->
            {#each Object.keys(dotMap) as rvtk}
                <div class="row">
                    <div class="col-12 col-12-xsmall">
                        <input type="radio" id="rvt-radio-{dotMap[rvtk].id}" on:click={handleSelect} value="{dotMap[rvtk].id}" name="rvts-radio" bind:group={selectedDOTUuid}>
                        <label for="rvt-radio-{dotMap[rvtk].id}">{dotMap[rvtk].url}</label>

                        {#if selectedDOTUuid === dotMap[rvtk].id}
                        <section class="rvt-mgmt">
                            <div class="row paddtobbottom">
                                <div class="col-12 col-12-xsmall">
                                    <a href="#" on:click|preventDefault={handleDoTestExecuteTo2} class="button primary fit small exec">Execute To2</a>
                                </div>
                                <div class="col-12 col-12-xsmall">
                                    <p class="rvt-info">{doTestExecuteErrorMessage}</p>
                                </div>
                            </div>
                            {#if dotMap[rvtk].to2.runs.length > 0}
                                {#each dotMap[rvtk].to2.runs as run}
                                <div class="row">
                                    <div class="col-12 col-12-xsmall">
                                        <input type="radio" id="trun-radio-{run.uuid}" value="{run.uuid}" name="testrun-radio" bind:group={selectedTestRunUuid}>
                                        <label for="trun-radio-{run.uuid}">TO{run.protocol} {(new Date(run.timestamp * 1000)).toLocaleString()} <a href="#" on:click|preventDefault={() => handleRemoveTestRun(run.uuid, run.protocol)}>X</a></label>
                                    </div>
                                </div>
                                {/each}
                            {/if}

                            {#if dotMap[rvtk].to2.runs.length == 0 && dotMap[rvtk].to2.runs.length == 0}
                                <div class="row">
                                    <div class="col-12 col-12-xsmall">
                                        <p class="rvt-info">No records found</p>
                                    </div>
                                </div>
                            {/if}

                            <div class="row">
                                <div class="col-12 col-12-xsmall">
                                    <a href="/api/dot/vouchers/{dotMap[rvtk].to2.id}"  class="button fit small exec">Download test vouchers</a>
                                </div>
                            </div>
                           
                        </section>
                        {/if}

                    </div>
                </div>
            {/each}


            <div class="row paddtobbottom">
                <div class="col-12 col-12-xsmall">
                {#if !newDoUiVisible}
                    <a href="#" on:click={handleInitiateNewDo} class="button primary">Add new DO</a>
                {:else}
                    <a href="#" on:click={handleCancelInitiateNewDo} class="button primary cancel">Cancel</a>
                {/if}
                </div>
            </div>
            
            {#if newDoUiVisible}
                <div class="row">
                    <div class="col-8 col-12-xsmall">
                        <input type="text" name="demo-name" bind:value={newDoUrl} id="demo-name" placeholder="DO URL">
                    </div>
                    <div class="col-4 col-12-xsmall">
                        <a href="#" on:click={handleAddNewDo} class="button primary">Add</a>
                    </div>
                </div>
                <div class="row">
                    <div class="col-12 col-12-xsmall">
                        <p>{newDoErrorMessage}</p>
                    </div>
                </div>
            {/if}
            
        </div>
        <div class="col-8 col-12-xsmall">
            {#if selectedTestRunUuid !== ""}
                <h2>TO{testRunMap[selectedTestRunUuid].protocol} Tests info for {dotMap[selectedDOTUuid].url} at {(new Date(testRunMap[selectedTestRunUuid].timestamp * 1000)).toLocaleString()}</h2>

                {#each Object.keys(testRunMap[selectedTestRunUuid].tests) as dotest}
                
                <div class="row rvt-test-case">
        
                    <div class="col-9 col-12-xsmall">
                        <p>{dotest}</p>
                    </div>
                    <div class="col-3 col-12-xsmall">
                        {#if testRunMap[selectedTestRunUuid].tests[dotest].passed}
                            <p class="success">Passed</p>
                        {:else}
                            <p class="failed">Failed</p>
                        {/if}
                    </div>
                    <div class="col-12 col-12-xsmall">
                        <p><b>{testRunMap[selectedTestRunUuid].tests[dotest].error}</b></p>
                    </div>
                </div>
                {/each}
            {:else}
                <h2>Tests info</h2>

                <div class="row">
                    <div class="col-12 col-12-xsmall">
                        <p>Test case was not selected</p>
                    </div>
                </div>
            {/if}
           
        </div>
    </div>
</section>