<script lang="ts">
    import {resetPasswordInit} from '../lib/User.api'
    import {push} from "svelte-spa-router"

    let errorMsg: string = ""
    let email: string = ""
    const handlePasswordChange = async (e) => {
        e.preventDefault()
        errorMsg = ""

        await resetPasswordInit(email)
        .then(() => {
            errorMsg = "You should now receive password reset link in your mail box. Please check your spam as well. If you still having issues, email certification@fidoalliance.org"
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
                        <input class="login_input" bind:value={email} type="email" placeholder="Your email address">
                    </div>
                    <div class="col-12">
                        <ul class="actions">
                            <li><input type="submit" on:click={handlePasswordChange} value="Reset password" class="primary" /></li>
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



