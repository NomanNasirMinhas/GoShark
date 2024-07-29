<script>
  import logo from "./../assets/images/logo.jpeg";
  import { userStore } from "./../store/store";
  import { Table, TableBody, TableBodyCell, TableBodyRow, TableHead, TableHeadCell, TableSearch } from 'flowbite-svelte';
  import { Drawer, CloseButton, A } from 'flowbite-svelte';
  import { InfoCircleSolid, ArrowRightOutline } from 'flowbite-svelte-icons';
  import { Input, ButtonGroup } from 'flowbite-svelte';
  import { SearchSolid } from 'flowbite-svelte-icons';
  import { sineIn } from 'svelte/easing';
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

  let ac_hidden8 = true;
  let ac_transitionParamsBottom = {
    y: 320,
    duration: 200,
    easing: sineIn
  };
  let ac_current_packet;

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
    <Drawer placement="bottom" width="w-full" transitionType="fly" transitionParams={ac_transitionParamsBottom} bind:hidden={ac_hidden8} id="sidebar8">
        <div class="flex items-center">
          <h5 id="drawer-label" class="inline-flex items-center mb-4 text-base font-semibold text-gray-500 dark:text-gray-400">
            <InfoCircleSolid class="w-5 h-5 me-2.5" />Info
          </h5>
          <CloseButton on:click={() => (ac_hidden8 = true)} class="mb-4 dark:text-white" />
        </div>
        <p class="max-w-lg mb-6 text-sm text-gray-500 dark:text-gray-400">
          {ac_current_packet["full_packet_data"]}
        </p>
        <Button color="light" href="/">Learn more</Button>
        <Button href="/" class="px-4">Get access <ArrowRightOutline class="w-5 h-5 ms-2" /></Button>
      </Drawer>

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
            await StopCapture();
            capture_started = false;
            
          } else {
            $userStore.requests = [];
            capture_started = true;
            await StartCapture(capture_filter, capture_promisc, "");
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

  <div class="mb-6 mt-16 w-96 ml-16">    
    <Input type="text" placeholder="Enter a filter" bind:value={searchTerm}>
      <SearchSolid slot="right" class="w-5 h-5 text-blue-500 dark:text-gray-400" />
    </Input>
  </div>
  <!-- {#if capture_started} -->
    <div class="packets_div">
        <Table>
            <TableHead>
              <TableHeadCell>Source IP</TableHeadCell>
              <TableHeadCell>Source Port</TableHeadCell>
              <TableHeadCell>L2-Protocol</TableHeadCell>
              <TableHeadCell>Destination IP</TableHeadCell>
              <TableHeadCell>Destination Port</TableHeadCell>              
              <TableHeadCell>Details</TableHeadCell>
            </TableHead>
            <TableBody tableBodyClass="divide-y">
              {#each filteredItems as item}              
                <TableBodyRow style="height: 30px; padding: 0%;">
                  <TableBodyCell>{item["layer_2"]["SrcIP"]}</TableBodyCell>
                  <TableBodyCell>{item["layer_3"]["SrcPort"].split("(")[0]}</TableBodyCell>
                  <TableBodyCell>{item["layer_2"]["Protocol"].split("(")[0]}</TableBodyCell>
                  <TableBodyCell>{item["layer_2"]["DstIP"]}</TableBodyCell>
                  <TableBodyCell>{item["layer_3"]["DstPort"].split("(")[0]}</TableBodyCell>
                    <TableBodyCell>
                        <Button
                        color="dark"
                        size='xs'
                        on:click={() => {
                            ac_current_packet = item;
                            ac_hidden8 = false;
                        }}
                        >
                        Details
                        </Button>
                    </TableBodyCell>
                </TableBodyRow>
              {/each}
            </TableBody>
          </Table>      
    </div>
  <!-- {/if} -->
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
    max-height: 900px;
    overflow-y: scroll;
    overflow-wrap: break-word;
    border: 1px solid #03104e;
    border-radius: 5px;
    padding: 10px;
    /* background-color: rgb(1, 29, 19); */
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
