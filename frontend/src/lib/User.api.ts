import {push} from "svelte-spa-router"

export const login = async (email:string, password:string): Promise<any> => {
    if (password.length == 0 && email.length == 0) {
        return Promise.reject("Missing email and/or password!")
    }

    let result = await fetch("/api/user/login", {
        method: "POST",
        headers: {
        "Content-Type": "application/json",
        },
        body: JSON.stringify({email, password}),
    })

    let resultJson = await result.json()

    if (result.status !== 200) {
        let statusText = result.statusText

        if (resultJson !== undefined && resultJson.errorMessage !== undefined) {
            statusText = resultJson.errorMessage
        }

        throw new Error(`Error sending request: ${statusText}`);
    }
}

export const isLoggedIn = async(): Promise<Boolean> => {
    let result = await fetch("/api/user/loggedin", {
        method: "GET",
        headers: {
        "Content-Type": "application/json",
        },
    })

    let resultJson = await result.json()

    if (result.status !== 200) {
        if (resultJson !== undefined && resultJson.errorMessage !== undefined) {
            return false
        }

        return false
    }

    return true
}

export const getConfig = async(): Promise<any> => {
    let result = await fetch("/api/user/config", {
        method: "GET",
        headers: {
            "Content-Type": "application/json",
        },
    })

    let resultJson = await result.json()

    return resultJson
}

export const loginOnprem = async (): Promise<any> => {
    let result = await fetch("/api/user/login/onprem", {
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

        throw new Error(`Error sending request: ${statusText}`);
    }
}

export const ensureUserIsLoggedIn = async(): Promise<any> => {
    return isLoggedIn()
    .then(isActually => {
        if (!isActually) {
            push("/")
        }
    })
}

export const logout = async(): Promise<Boolean> => {
    let result = await fetch("/api/user/logout", {
        method: "POST",
        headers: {
        "Content-Type": "application/json",
        },
    })

    let resultJson = await result.json()

    if (result.status !== 200) {
        if (resultJson !== undefined && resultJson.errorMessage !== undefined) {
            return false
        }

        return false
    }

    return true
}


export const purgeTests = async(): Promise<Boolean> => {
    let result = await fetch("/api/user/purgetests", {
        method: "POST",
        headers: {
        "Content-Type": "application/json",
        },
    })

    let resultJson = await result.json()

    if (result.status !== 200) {
        if (resultJson !== undefined && resultJson.errorMessage !== undefined) {
            return false
        }

        return false
    }

    return true
}


export const register = async (password: String, passwordRepeat:string, email: string, company:string, name:string, phone:string): Promise<any> => {
    if (password.length == 0
    || passwordRepeat.length == 0
    || email.length == 0
    || name.length == 0
    || company.length == 0
    || phone.length == 0) {
        throw new Error("Missing required field!");
    }

    if (password !== passwordRepeat) {
        throw new Error("Passwords do not match!");
    }

    let result = await fetch("/api/user/register", {
        method: "POST",
        headers: {
        "Content-Type": "application/json",
        },
        body: JSON.stringify({email, password, name, company, phone}),
    })

    let resultJson = await result.json()

    if (result.status !== 200) {
        let statusText = result.statusText

        if (resultJson !== undefined && resultJson.errorMessage !== undefined) {
            statusText = resultJson.errorMessage
        }

        throw new Error(`Error sending request: ${statusText}`);
    }

    if (resultJson.status === "ok") {
        return Promise.resolve()
    } else {
        throw new Error("Unexpected error");
    }
}

export const requestNewEmailValidationEmail = async (): Promise<any> => {
    let result = await fetch("/api/user/email/resendverification", {
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

        throw new Error(`Error sending request: ${statusText}`);
    }

    if (resultJson.status === "ok") {
        return Promise.resolve()
    } else {
        throw new Error("Unexpected error");
    }
}

export const completeOAuth2Reg = async (company:string, name:string, phone:string): Promise<any> => {
    if (name.length == 0
    || company.length == 0
    || phone.length == 0) {
        throw new Error("Missing required field!");
    }

    let result = await fetch("/api/user/register/additionalinfo", {
        method: "POST",
        headers: {
        "Content-Type": "application/json",
        },
        body: JSON.stringify({name, company, phone}),
    })

    let resultJson = await result.json()

    if (result.status !== 200) {
        let statusText = result.statusText

        if (resultJson !== undefined && resultJson.errorMessage !== undefined) {
            statusText = resultJson.errorMessage
        }

        throw new Error(`Error sending request: ${statusText}`);
    }

    if (resultJson.status === "ok") {
        return Promise.resolve()
    } else {
        throw new Error("Unexpected error");
    }
}



export const resetPasswordInit = async (email: String): Promise<any> => {
    if (email.length == 0) {
        throw new Error("Missing required field!");
    }

    let result = await fetch("/api/user/password/reset/init", {
        method: "POST",
        headers: {
        "Content-Type": "application/json",
        },
        body: JSON.stringify({email}),
    })

    let resultJson = await result.json()

    if (result.status !== 200) {
        let statusText = result.statusText

        if (resultJson !== undefined && resultJson.errorMessage !== undefined) {
            statusText = resultJson.errorMessage
        }

        throw new Error(`Error sending request: ${statusText}`);
    }

    if (resultJson.status === "ok") {
        return Promise.resolve()
    } else {
        throw new Error("Unexpected error");
    }
}


export const resetPasswordApply = async (password: String, passwordRepeat:string): Promise<any> => {
    if (password.length == 0
    || passwordRepeat.length == 0) {
        throw new Error("Missing required field!");
    }

    if (password !== passwordRepeat) {
        throw new Error("Passwords do not match!");
    }

    let result = await fetch("/api/user/password/reset", {
        method: "POST",
        headers: {
        "Content-Type": "application/json",
        },
        body: JSON.stringify({
            password: password,
            confirm_password: password
        }),
    })

    let resultJson = await result.json()

    if (result.status !== 200) {
        let statusText = result.statusText

        if (resultJson !== undefined && resultJson.errorMessage !== undefined) {
            statusText = resultJson.errorMessage
        }

        throw new Error(`Error sending request: ${statusText}`);
    }

    if (resultJson.status === "ok") {
        return Promise.resolve()
    } else {
        throw new Error("Unexpected error");
    }
}


const getOauth2RedirectUrl = async (provider: string): Promise<any> => {
    let result = await fetch(`/api/oauth2/${provider}/init`, {
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

        throw new Error(`Error sending request: ${statusText}`);
    }

    if (resultJson.status === "ok") {
        return Promise.resolve(resultJson.redirect_url)
    } else {
        throw new Error("Unexpected error");
    }
}


export const getGithubRedirectUrl = async (): Promise<any> => {
    return getOauth2RedirectUrl("github")
}

export const getGoogleRedirectUrl = async (): Promise<any> => {
    return getOauth2RedirectUrl("google")
}