<script>
  import logo from "./../assets/images/logo.jpeg";
  import { userStore } from "./../store/store";
  import { Table, TableBody, TableBodyCell, TableBodyRow, TableHead, TableHeadCell, TableSearch } from 'flowbite-svelte';
  import {
    Navbar,
    NavBrand,
    NavLi,
    NavUl,
    NavHamburger,
  } from "flowbite-svelte";
  import { PlaySolid, StopSolid } from "flowbite-svelte-icons";
  import { Button } from "flowbite-svelte";
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
  // writeable interface array

  let isAdmin;
  let capture_started = false;
  let searchTerm = '';
  let capture_filter = "";
  let capture_iface = "";
  let capture_promisc = false;

  const interfaces = writable([]);
  // Create a new store with the given data.
  let requests = [];

  $: filteredItems = $userStore.requests.filter((item) => JSON.stringify(item).toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1);
  function parsePcapData(pcapData) {
    try {
      let packet = {};
      let parsed_packet = {};
      let packetData = pcapData.split("--- Layer 1 ---");
      packet["full_packet_data"] = packetData[0]
        .split("------------------------------------")[1]
        .trim();
      let temp = packetData[1].split("--- Layer 2 ---");
      packet["layer_1"] = temp[0].trim();
      temp = temp && temp.length > 1 ? temp[1].split("--- Layer 3 ---") : null;
      packet["layer_2"] = temp && temp.length > 0 ? temp[0].trim() : null;
      temp = temp && temp.length > 1 ? temp[1].split("--- Layer 4 ---") : null;
      packet["layer_3"] = temp && temp.length > 0 ? temp[0].trim() : null;
      temp = temp && temp.length > 1 ? temp[1].split("--- Layer 5 ---") : null;
      packet["layer_4"] = temp && temp.length > 0 ? temp[0].trim() : null;
      packet["layer_5"] = temp && temp.length > 1 ? temp[1].trim() : null;

      packet["layer_1"] = packet["layer_1"]
        ? packet["layer_1"].split(" ")
        : null;
      packet["layer_2"] = packet["layer_2"]
        ? packet["layer_2"].split(" ")
        : null;
      packet["layer_3"] = packet["layer_3"]
        ? packet["layer_3"].split(" ")
        : null;
      packet["layer_4"] = packet["layer_4"]
        ? packet["layer_4"].split(" ")
        : null;
      packet["layer_5"] = packet["layer_5"]
        ? packet["layer_5"].split(" ")
        : null;

      let packets_keys = Object.keys(packet);
      for (let i = 0; i < packets_keys.length; i++) {
        if (packets_keys[i] === "full_packet_data") {
          parsed_packet[packets_keys[i]] = packet[packets_keys[i]];
        } else {
          if (packet[packets_keys[i]] && packet[packets_keys[i]].length > 1) {
            let temp = packet[packets_keys[i]];
            let temp_obj = {};
            for (let j = 0; j < temp.length; j++) {
              if (j === 0) {
                let key = "Protocol";
                let value = temp[j].trim().split("\t")[0];
                if (key && value) temp_obj[key] = value;
              } else {
                let key = temp[j].split("=")[0];
                let value = temp[j].split("=")[1];
                if (key && value) temp_obj[key] = value;
              }
            }
            parsed_packet[packets_keys[i]] = temp_obj;
          }
        }
      }

    //   console.log("packet", parsed_packet);
      return parsed_packet;
    } catch (err) {
      console.log("Error in parsePcapData", err);
    }
  }

  onMount(async () => {
    try {
      capture_filter = $userStore.capture_iface;
      capture_promisc = $userStore.capture_promisc;
      const ws = new WebSocket("ws://localhost:4444/ws");

      ws.addEventListener("message", (message) => {
        let pcapData = parsePcapData(message.data);        
        console.log("Received message from server: ", pcapData);
        console.log("Layer 1", pcapData["layer_1"]);        
        userStore.update((state) => {
          state.requests.push(pcapData);
          return state;
        });
      });

      StartCapture(capture_filter, capture_promisc, "");
      capture_started = true;
    } catch (err) {
      console.log("Error in onMount", err);
    }
  });
</script>

<main>
  <Navbar>
    <NavBrand href="/">
      <img src={logo} class="me-3 h-6 sm:h-9" alt="Flowbite Logo" />
      <span
        class="self-center whitespace-nowrap text-xl font-semibold dark:text-white"
        >GoShark</span
      >
    </NavBrand>
    <div class="flex md:order-2">
      <Button
        size="sm"
        color={capture_started ? "red" : "green"}
        on:click={async () => {
          if (capture_started) {
            StopCapture();
            capture_started = false;
            
          } else {
            StartCapture(capture_filter, capture_promisc, "");
            capture_started = true;
            $userStore.requests = [];
          }
        }}
      >
        {#if capture_started}
          <StopSolid class="w-5 h-5 me-2" />
          Stop Capturing
        {:else}
          <PlaySolid class="w-5 h-5 me-2" />
          Start Capturing
        {/if}
      </Button>
      <NavHamburger />
    </div>
  </Navbar>

  {#if capture_started}
    <div class="packets_div">
      {#each $userStore.requests as request}
        <div
          style="display: flex; flex-direction: row; align-items: center; justify-content: space-between;"
        >
          <p class="request">
            {#if request["layer_3"]}
                <p>{request["layer_2"]["SrcIP"]}</p>
                <p>{request["layer_3"]["SrcPort"].split("(")[0]}</p>
                <p>{request["layer_2"]["DstIP"]}</p>
                <p>{request["layer_3"]["DstPort"].split("(")[0]}</p>
            {:else}
                <p>{request["layer_1"]["SrcMAC"]}</p>
                <p>{request["layer_1"]["DstMAC"]}</p>
            {/if}
            <!-- {Object.keys(request["layer_1"]).join(" ")} -->
            <!-- {request["layer_3"] ? `${request["layer_2"]["SrcIP"]}\t${request["layer_3"]["SrcPort"].split("(")[0]} 
          \t ${request["layer_2"]["DstIP"]}\t${request["layer_3"]["DstPort"].split("(")[0]}` : `${request["layer_1"]["SrcMAC"]}:${request["layer_1"]["DstMAC"]}`} -->
          </p>
          <!-- <Button
            color="purple"    
            size='sm'        
            >Details</Button
          > -->
        </div>
      {/each}
    </div>
  {/if}
</main>

<style>
  #logo {
    display: block;
    /* width: 30%; */
    height: 300px;
    margin: auto;
    padding: 2% 0 0;
    background-position: center;
    background-repeat: no-repeat;
    background-size: 100% 100%;
    background-origin: content-box;
  }

  .request {
    height: 20px;
    margin: 0;
    padding-left: 10px;
    padding-right: 10px;
    font-size: 12px;
    font-style: italic;
    color: #fff;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    width: 100%;
    border: #e2ebf0 1px solid;
    background-color: rgb(41, 1, 45);
    margin-bottom: 10px;
    display: flex;
    flex-direction: row;
    align-items: center;
    justify-content: space-between;
  }

  .packets_div {
    margin: 1.5rem auto;
    width: 95%;
    height: 95%;
    overflow-y: scroll;
    overflow-wrap: break-word;
    border: 1px solid #03104e;
    border-radius: 5px;
    padding: 10px;
    background-color: rgb(1, 29, 19);
  }

  .result {
    height: 20px;
    line-height: 20px;
    margin: 1.5rem auto;
  }

  .input-box {
    display: flex;
    flex-direction: column;
    justify-content: space-evenly;
    align-items: flex-start;
    margin: 1.5rem auto;
    width: 80%;
    height: 300px;
    border: 5px solid #f4f5f6;
    padding: 20px;
  }

  .input-box .btn {
    width: 60px;
    height: 30px;
    line-height: 30px;
    border-radius: 3px;
    border: none;
    margin: 0 0 0 20px;
    padding: 0 8px;
    cursor: pointer;
  }

  .input-box .btn:hover {
    background-image: linear-gradient(to top, #cfd9df 0%, #e2ebf0 100%);
    color: #333333;
  }

  .input-box .input {
    border: none;
    border-radius: 3px;
    outline: none;
    height: 30px;
    line-height: 30px;
    padding: 0 10px;
    background-color: rgba(240, 240, 240, 1);
    -webkit-font-smoothing: antialiased;
  }

  .input-box .input:hover {
    border: none;
    background-color: rgba(255, 255, 255, 1);
  }

  .input-box .input:focus {
    border: none;
    background-color: rgba(255, 255, 255, 1);
  }
</style>
