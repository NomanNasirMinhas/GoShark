<script>
    import logo from "./../assets/images/logo.png";
    import { Button } from "flowbite-svelte";
    import { userStore } from './../store/store';
    import { Label, Select } from "flowbite-svelte";
    import {
      Greet,
      IsRoot,
      StartCapture,
      GetAllDevices,
      StopCapture,
      CheckLibcapAndInstall
    } from "../../wailsjs/go/main/App.js";
    import { onMount } from "svelte";
    import { writable } from "svelte/store";
    import { get } from "svelte/store";
    import { navigate } from "svelte-routing";
    // writeable interface array
  
    let isAdmin;
    let isLibcapInstalled;
      
    onMount(async () => {
      try {
        isAdmin = await IsRoot();
        // isLibcapInstalled = await CheckLibcapAndInstall();
        console.log("isAdmin", isAdmin);
        // console.log("isLibcapInstalled", isLibcapInstalled);
        if (isAdmin){
            setTimeout(() => {
                navigate("/home");
            }, 3000);
        }        
      } catch (err) {
        console.log("Error in onMount", err);
      }
    });
  </script>
  
  <main>
    <div class="flex flex-col justify-evenly h-screen">

        <img alt="Wails logo" id="logo" src={logo} />
        <h1 class="header h-64">GoShark</h1>
        <!-- <p style="margin-top: -50px;" class="text-lg dark:text-white">GoShark</p> -->
        <!-- <div class="result" id="result">{resultText}</div> -->
        {#if !isAdmin}
        <h4 class="err-msg" id="result">
            You are not an admin. Please run the program as an admin.
        </h4>
        {:else}
        <h4 class="ok-msg" id="result">
            Loading ......
        </h4>
        {/if}
    </div>

  </main>
  
  <style>
    #logo {
      display: block;
      /* width: 30%; */
      height: 70%;
      margin: auto;
      /* margin-top: 10%; */
      /* padding: 2% 0 0; */
      background-position: center;
      background-repeat: no-repeat;
      background-size: 100% 100%;
      background-origin: content-box;
    }
  
    .header {
      text-align: center;
      font-size: 6rem;      
    }

    .err-msg {
      text-align: center;
      font-size: 1rem;
      color: red;
    }

    .ok-msg {
      text-align: center;
      font-size: 1rem;
      color: rgb(244, 247, 245);
    }

  </style>
  