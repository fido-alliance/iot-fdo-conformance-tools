
export const getDeviceTestRunsList = async (): Promise<Array<any>> => {
    let result = await fetch("/api/device/testruns", {
        method: "GET",
        headers: {
        "Content-Type": "application/json",
        },
    })

    let resultJson = await result.json()

    if (result.status !== 200) {
        let statusText = result.statusText

        if (resultJson !== undefined && resultJson.errorMessage !== undefined) {
            statusText = resultJson.errorMessage
        }

        return Promise.reject(`Error sending request: ${statusText}`)
    }

    return resultJson.entries
}

export const addNewDevice = async (name, voucher): Promise<Array<any>> => {
    let result = await fetch("/api/device/create", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({name, voucher})
    })

    let resultJson = await result.json()

    if (result.status !== 200) {
        let statusText = result.statusText

        if (resultJson !== undefined && resultJson.errorMessage !== undefined) {
            statusText = resultJson.errorMessage
        }

        return Promise.reject(`Error sending request: ${statusText}`)
    }

    return resultJson.entries
}


export const removeTestRun = async (toprotocol: string, id: string, testRunId: string): Promise<Array<any>> => {
    let result = await fetch(`/api/device/testruns/${toprotocol}/${id}/${testRunId}`, {
        method: "DELETE",
        headers: {
            "Content-Type": "application/json",
        },
    })

    let resultJson = await result.json()

    if (result.status !== 200) {
        let statusText = result.statusText

        if (resultJson !== undefined && resultJson.errorMessage !== undefined) {
            statusText = resultJson.errorMessage
        }

        return Promise.reject(`Error sending request: ${statusText}`)
    }

    return resultJson.rvts
}


export const addNewTestRun = async (toprotocol: number, id: string): Promise<Array<any>> => {
    let result = await fetch(`/api/device/testruns/${toprotocol}/${id}`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
    })

    let resultJson = await result.json()

    if (result.status !== 200) {
        let statusText = result.statusText

        if (resultJson !== undefined && resultJson.errorMessage !== undefined) {
            statusText = resultJson.errorMessage
        }

        return Promise.reject(`Error sending request: ${statusText}`)
    }

    return resultJson.rvts
}

