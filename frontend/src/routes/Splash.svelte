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
    } from "../../wailsjs/go/main/App.js";
    import { onMount } from "svelte";
    import { writable } from "svelte/store";
    import { get } from "svelte/store";
    import { navigate } from "svelte-routing";
    // writeable interface array
  
    let isAdmin;
    
  
    const interfaces = writable([]);
    // Create a new store with the given data.
    let requests = [];
  
    // let resultText = "Please enter your name below 👇"
    // let name
  
  
  
    onMount(async () => {
      try {
        isAdmin = await IsRoot();
        // if (isAdmin){
        //     setTimeout(() => {
        //         navigate("/home");
        //     }, 10000);
        // }        
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
        <div class="result" id="result">
            You are not an admin. Program will not work properly.
        </div>
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
      /* font-weight: bold; */
      /* margin-top: 20px; */
      /* font-family: 'Times New Roman', Times, serif; */
    }
  </style>
  