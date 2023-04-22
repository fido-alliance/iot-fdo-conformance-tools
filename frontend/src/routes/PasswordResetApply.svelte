<script lang="ts">
    import {resetPasswordApply} from '../lib/User.api'
    import {push} from "svelte-spa-router"

    let errorMsg: string = ""
    let password: string = ""
    let passwordRepeat: string = ""

    const handlePasswordReset = async (e) => {
        e.preventDefault()
        errorMsg = ""

        await resetPasswordApply(password, passwordRepeat)
        .then(() => {
            errorMsg = "Password has been updated"
            window.setTimeout(() => push("/"), 2500)
        })
        .catch((err) => {
            errorMsg = err
        })
    }
</script>

<section id="intro" class="main">
    <div class="spotlight">
        <div class="content">
            <header class="major">
                <h2>Reset your password</h2>
            </header>

            <form method="post" action="#">
                <div class="row gtr-uniform">
                    <div class="col-6 col-12-xsmall">
                        <input class="login_input" bind:value={password} type="password" placeholder="Password">
                    </div>
                    <div class="col-6 col-12-xsmall">
                        <input class="login_input" bind:value={passwordRepeat} type="password" placeholder="Confirm your password">
                    </div>
                    <div class="col-12">
                        <ul class="actions">
                            <li><input type="submit" on:click={handlePasswordReset} value="Set new password" class="primary" /></li>
                        </ul>
                    </div>
                    <div class="col-12">
                        <p>{errorMsg}</p>
                    </div>
                </div>
            </form>
        </div>
    </div>
</section>



