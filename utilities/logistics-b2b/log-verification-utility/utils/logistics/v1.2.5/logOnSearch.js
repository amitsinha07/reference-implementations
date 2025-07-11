const _ = require("lodash");
const dao = require("../../../dao/dao");
const constants = require("../../constants");
const utils = require("../../utils");
const { reverseGeoCodingCheck } = require("../../reverseGeoCoding");

const checkOnSearch = async (data, msgIdSet) => {
  const onSrchObj = {};
  let onSearch = data;
  const domain = data?.context?.domain;
  let core_version = onSearch.context.core_version;
  const timestamp = onSearch.context.timestamp;
  const contextTimestamp = new Date(timestamp || "");
  let search = dao.getValue("searchObj");
  let validFulfillmentIDs = new Set();
  const cod_order = dao.getValue("cod_order");
  const quick_commerce = dao.getValue("quick_commerce");
  const search_fulfill_request = dao.getValue("search_fulfill_request");
  const codified_static_terms = dao.getValue("codified_static_terms") || false;
  onSearch = onSearch.message.catalog;
  let avgPickupTime;
  /**
   * Extracts the number of days from a duration string in ISO 8601 format.
   *
   * @param {string} duration - The duration string to parse (e.g. "P30D").
   * @returns {number} The number of days extracted from the duration string, or 0 if the string is invalid.
   */
  const getDurationInDays = (duration) => {
    // Regular expression to match the duration string in ISO 8601 format (PXD)
    const match = duration.match(/^P(\d+)D$/);

    // If the string matches the pattern, return the extracted number of days as an integer
    return match ? parseInt(match[1], 10) : 0;
  };

  const formatDate = (date) => {
    return date.toISOString().split("T")[0];
  };

  /**
   * Validates the timestamp of an item in the on_search response.
   *
   * @param {object} item - The item to validate.
   * @returns {boolean} Whether the timestamp is valid.
   *
   * The timestamp is considered valid if the duration is not provided or is invalid.
   * If the duration is valid, the timestamp is considered valid if it is equal to the
   * current timestamp plus the duration.
   */
  const validateTimestamp = (item) => {
    const duration = item.time?.duration || "";
    const expectedDays = getDurationInDays(duration);

    if (expectedDays === 0) return true; // No duration or invalid format

    const currentTimestamp = new Date(contextTimestamp);
    currentTimestamp.setUTCDate(contextTimestamp.getUTCDate() + expectedDays);
    const expectedDate = formatDate(currentTimestamp);

    const itemTimestamp = new Date(item.time?.timestamp || "");
    const itemDate = formatDate(itemTimestamp);
    console.log(itemDate, expectedDate);

    return itemDate === expectedDate;
  };

  try {
    console.log(
      `Checking TAT for category or item in ${constants.LOG_ONSEARCH} api`
    );

    if (quick_commerce) {
      const provider = onSearch["bpp/providers"][0];
      provider?.categories?.forEach((it, i) => {
        if (it.id !== "Instant Delivery")
          onSrchObj[
            `quick_commerce_categoriesId_Err_${i}`
          ] = `Categories id should be Instant Delivery for flow quick commerce logistics.`;
        const duration = it?.time?.duration || "";
        if (duration) {
          const match = duration.match(/^PT(\d+)M$/);
          const minutes = match ? parseInt(match[1], 10) : null;

          if (minutes === null || minutes > 10) {
            onSrchObj[
              `quick_commerce_duration_Err_${i}`
            ] = `Duration should be less than or equal to 10 minutes (PT10M or less). Found: ${duration} for quick commerce flow`;
          }
        }

        const fulfillmentBatch = provider?.fulfillments?.find(
          (i) => i.type === "Batch"
        );
        if (!fulfillmentBatch) {
          onSrchObj[
            `quick_commerce_fulfillmentType_Err_${i}`
          ] = `Fulfillment type "Batch" should be there is fulfillments array for quick commerce logistics`;
        } else {
          if (fulfillmentBatch?.tags) {
            const fulfillRequestTag = fulfillmentBatch.tags.find(
              (tag) => tag.code === "fulfill_request"
            );
            const fulfillResponseTag = fulfillmentBatch.tags.find(
              (tag) => tag.code === "fulfill_response"
            );

            if (!fulfillRequestTag) {
              onSrchObj[
                `quick_commerce_fulfillRequestTag_Err_${i}`
              ] = `Fulfillment tags should include a code 'fulfill_request' for quick commerce logistics`;
            } else {
              const sortedList1 = _.sortBy(search_fulfill_request, "code");
              const sortedList2 = _.sortBy(fulfillRequestTag, "code");

              const areEqual =
                _.isEqual(sortedList1, sortedList2) &&
                search_fulfill_request.code === fulfillRequestTag.code;

              if (!areEqual) {
                onSrchObj[
                  `quick_commerce_fulfillReuqest_${i}`
                ] = `Fulfillment tags code 'fulfill_request' doesnot match with the one provided in search payload for quick commerce logistics`;
              }
            }

            if (!fulfillResponseTag) {
              onSrchObj[
                `quick_commerce_fulfillResponseTag_Err_${i}`
              ] = `Fulfillment tags should include a code 'fulfill_response' for quick commerce logistics`;
            } else {
              const requiredCodes = [
                "rider_count",
                "order_count",
                "rate_basis",
              ];

              let allCodesPresent = true;

              requiredCodes.forEach((code) => {
                const exists = fulfillResponseTag.list.some(
                  (item) => item.code === code
                );
                if (!exists) {
                  onSrchObj[
                    `fulfill_response_missing_${code}`
                  ] = `Code '${code}' is missing in fulfill_response list for quick commerce flow.`;
                  allCodesPresent = false;
                }
              });

              if (allCodesPresent)
                dao.setValue("on_search_fulfill_response", fulfillResponseTag);
            }
          } else
            onSrchObj[
              `quick_commerce_fulfillmenttags`
            ] = `Fulfillment tags is missing.`;
        }
      });
    }

    if (codified_static_terms) {
      if (!onSearch["bpp/descriptor"]?.tags) {
        onSrchObj.codifiedStaticTermsErr = `bpp/descriptor/tags is mandatory in ${constants.LOG_ONSEARCH} api for codified static terms flow`;
      } else {
        const descriptorTags = onSearch["bpp/descriptor"].tags.find(
          (tag) => tag.code === "bpp_terms"
        );

        if (!descriptorTags || !Array.isArray(descriptorTags.list)) {
          onSrchObj.bppTermsErr = `bpp_terms tag or its list array is missing in bpp/descriptor/tags`;
        } else {
          const requiredKeys = [
            "max_liability",
            "max_liability_cap",
            "mandatory_arbitration",
            "court_jurisdiction",
            "delay_interest",
          ];

          const missingKeys = requiredKeys.filter(
            (key) =>
              !descriptorTags.list.some(
                (item) => item.code === key && item.value
              )
          );

          if (missingKeys.length > 0) {
            onSrchObj.bppTermsMissingKeys = `The following keys are missing or have no value in bpp_terms: ${missingKeys.join(
              ", "
            )}`;
          } else {
            dao.setValue("codifiedbppTermsList", descriptorTags.list);
          }
        }
      }
    }

    if (onSearch.hasOwnProperty("bpp/providers")) {
      onSearch["bpp/providers"].forEach((provider) => {
        if (cod_order) {
          if (!provider?.tags) {
            onSrchObj.codOrder = `cod_order tag is mandatory in ${constants.LOG_ONSEARCH} call "bpp/provider/tags"`;
          } else if (
            !provider.tags.some(
              (tag) =>
                tag.code === "special_req" &&
                tag.list?.some((item) => item.code === "cod_order")
            )
          ) {
            onSrchObj.codOrder = `cod_order tag is mandatory in ${constants.LOG_ONSEARCH} call in "bpp/provider/tags"`;
          }
        }
        provider?.categories?.forEach((category) => {
          const catName = category?.id;
          const categoryTime = category?.time;
          const currentDate = timestamp.split("T")[0];
          const dateObj = new Date(currentDate);
          const nextDate = new Date(dateObj.setDate(dateObj.getDate() + 1))
            .toISOString()
            .split("T")[0];
          const categoryTimestamp =
            core_version == "1.1.0"
              ? categoryTime?.timestamp?.split("T")[0]
              : categoryTime?.timestamp;

          if (
            (catName == "Same Day Delivery" ||
              catName == "Immediate Delivery") &&
            categoryTimestamp &&
            categoryTimestamp != currentDate
          ) {
            onSrchObj.catTAT = `For Same Day Delivery/Immediate Delivery, TAT date should be the same date i.e. ${currentDate}`;
          }
          if (
            catName == "Next Day Delivery" &&
            categoryTimestamp &&
            categoryTimestamp != nextDate
          ) {
            onSrchObj.catTAT = `For Next Day Delivery, TAT date should be the next date i.e. ${nextDate}`;
          }
          provider?.items?.forEach((item, i) => {
            if (domain === "ONDC:LOG10" && !item?.time?.timestamp) {
              onSrchObj[
                `Item${i}_timestamp`
              ] = `Timestamp is mandatory inside time object for item ${item.id} in ${constants.LOG_ONSEARCH} api in order type P2P (ONDC:LOG10)`;
            }
            const catId = item?.category_id;
            const itemTime = item?.time;
            const itemTimestamp =
              core_version == "1.1.0"
                ? itemTime?.timestamp?.split("T")[0]
                : itemTime?.timestamp;
            if (catName === catId && !categoryTime && !itemTime)
              onSrchObj.TAT = `Either Category level TAT or Item level TAT should be given in ${constants.LOG_ONSEARCH} api for category "${catName}"`;
            if (
              (catId == "Same Day Delivery" || catId == "Immediate Delivery") &&
              itemTimestamp &&
              itemTimestamp != currentDate
            ) {
              onSrchObj.itemTAT = `For Same Day Delivery/Immediate Delivery, TAT date should be the same date i.e. ${currentDate}`;
            }
            if (
              catId == "Next Day Delivery" &&
              itemTimestamp &&
              itemTimestamp != nextDate
            ) {
              onSrchObj.itemTAT = `For Next Day Delivery, TAT date should be the next date i.e. ${nextDate}`;
            }
            try {
              console.log("Validating items timestamp");

              if (!validateTimestamp(item)) {
                let itemKey = `itemTimestampErr${i}`;
                onSrchObj[
                  itemKey
                ] = `Item timestamp '${item.time.timestamp}' is not as expected for item ${item?.id}, should be relative to context/timestamp`;
              }
            } catch (e) {
              console.log("Error while validating item timestamps", e);
            }
          });
          if (cod_order) {
            if (provider?.items?.length === 1)
              onSearch.CodItemErr = `For COD order, there should be more than one item in the order`;
            else {
              // dao.setValue("COD_ITEM", provider?.items);
              const codItem = provider?.items?.filter(
                (item) =>
                  item.tags &&
                  item.tags.some(
                    (tag) =>
                      tag.code === "type" &&
                      tag.list.some((entry) => entry.value === "cod")
                  )
              );
              if (!codItem)
                onSrchObj.codOrderItemErr = `Tags is missing for COD order item`;
              else {
                dao.setValue("COD_ITEM", codItem);
              }
            }
          }
        });
      });
    }
  } catch (error) {
    console.log(`!!Error while fetching category and item TAT`, error);
  }

  //forward and backward shipment
  try {
    console.log(
      `Checking forward and backward shipment in ${constants.LOG_ONSEARCH} api`
    );
    function validateFulfillments(categories, fulfillments) {
      // Filter all Delivery fulfillments
      const deliveryFulfillments = fulfillments.filter(
        (f) => f.type === "Delivery"
      );

      // Check if there are at least two categories
      if (categories.length >= 2) {
        // Ensure there is a Delivery fulfillment for each category
        if (deliveryFulfillments.length !== categories.length) {
          onSrchObj.flflmentsErr = `Separate fulfillments should be created for each category as the estimate pickup time could be different`;
        }

        // Optionally, check that each fulfillment is unique (if needed)
        const uniqueFulfillments = new Set(
          deliveryFulfillments.map((f) => f.id)
        );
        if (uniqueFulfillments.size !== deliveryFulfillments.length) {
          onSrchObj.flflmentsErr1 = `Delivery' fulfillments should have unique IDs`;
        }
      }

      return;
    }

    validateFulfillments(
      onSearch["bpp/providers"][0].categories,
      onSearch["bpp/providers"][0].fulfillments
    );
    if (
      onSearch["bpp/fulfillments"] ||
      onSearch["bpp/providers"][0].fulfillments
    ) {
      const fulfillments =
        core_version === "1.1.0"
          ? onSearch["bpp/fulfillments"]
          : onSearch["bpp/providers"][0].fulfillments;

      dao.setValue("bppFulfillmentsArr", fulfillments);

      let hasForwardShipment = false;
      let hasBackwardShipment = false;

      for (const fulfillment of fulfillments) {
        validFulfillmentIDs.add(fulfillment.id);
        if (
          fulfillment.type === "Prepaid" ||
          fulfillment.type === "CoD" ||
          fulfillment.type === "Delivery" ||
          fulfillment.type === "Batch"
        ) {
          hasForwardShipment = true;
          avgPickupTime = fulfillment?.start?.time?.duration;
          dao.setValue(`${fulfillment?.id}-avgPickupTime`, avgPickupTime);
        } else if (
          fulfillment.type === "RTO" ||
          fulfillment.type === "Reverse QC" ||
          fulfillment.type === "Return"
        ) {
          hasBackwardShipment = true;
          if (fulfillment.type === "RTO") dao.setValue("rtoID", fulfillment.id);
        }
      }

      if (hasForwardShipment && hasBackwardShipment) {
        console.log("Both forward and backward shipments are present.");
      } else if (!hasForwardShipment) {
        onSrchObj.frwrdShpmnt = `Forward shipment is missing in fulfillments in ${constants.LOG_ONSEARCH} api`;
      } else if (!hasBackwardShipment) {
        onSrchObj.bkwrdshmpnt = `Backward shipment is missing in fulfillments in ${constants.LOG_ONSEARCH} api`;
      }
    }
  } catch (error) {
    console.log(
      `!!Error while checking forward/backward shipment in ${constants.LOG_ONSEARCH} api`,
      error
    );
  }

  try {
    console.log(
      `Checking item fulfillment_id corresponding to one of the ids in bpp/fulfillments in ${constants.LOG_ONSEARCH} api`
    );
    if (onSearch["bpp/providers"]) {
      let providers = onSearch["bpp/providers"];
      dao.setValue("providersArr", providers);
      providers.forEach((provider, i) => {
        let itemsArr = provider.items;
        const providerId = provider.id;

        dao.setValue(`${providerId}itemsArr`, itemsArr);
        itemsArr.forEach((item, j) => {
          if (quick_commerce) {
            if (item?.category_id !== "Instant Delivery")
              onSrchObj[
                `quick_commerce_itemCategoryId_Err_${j}`
              ] = `item id with ${item?.id} category id should be "Instant Delivery" for quick commerce logistics flow.`;
            if (item?.tags) {
              const typeTag = item.tags.find((tag) => tag.code === "type");

              if (!typeTag) {
                onSrchObj[
                  `quick_commerce_itemTagsCode_Err_${j}`
                ] = `Item with id ${item?.id} should have a tag with code "type" for quick commerce logistics flow.`;
              } else {
                const typeEntry = typeTag.list?.find(
                  (entry) => entry.code === "type" && entry.value === "rider"
                );

                if (typeEntry) {
                  const unitEntry = typeTag.list?.find(
                    (entry) => entry.code === "unit"
                  );
                  if (!unitEntry) {
                    onSrchObj[
                      `quick_commerce_itemTagsUnit_Err_${j}`
                    ] = `Item with id ${item?.id} should have a code "unit" in the "type" tag list when "type" value is "rider".`;
                  }
                } else {
                  const typeExists = typeTag.list?.some(
                    (entry) => entry.code === "type"
                  );
                  if (!typeExists) {
                    onSrchObj[
                      `quick_commerce_itemTagsType_Err_${j}`
                    ] = `Item with id ${item?.id} should have a code "type" in the "type" tag list.`;
                  }
                }
              }
            } else {
              onSrchObj[
                `quick_commerce_itemTags_Err_${j}`
              ] = `Item with id ${item?.id} should have tags for quick commerce logistics flow.`;
            }
          }

          const typeTag = item?.tags?.find((tag) => tag.code === "type");
          const surgeInfo = typeTag?.list?.find(
            (i) => i.code === "type" && i.value === "surge"
          );

          if (surgeInfo) {
            dao.setValue("is_surge_item", true);
            dao.setValue("surge_item", item);
          }

          if (!validFulfillmentIDs.has(item.fulfillment_id)) {
            onSrchObj.fulfillmentIDerr = `fulfillment_id - ${item.fulfillment_id} of /items/${j} does not match with any id in fulfillments array in ${constants.LOG_ONSEARCH} api`;
          }
          if (
            item.descriptor.code === "P2H2P" &&
            !search["@ondc/org/payload_details"].dimensions
          ) {
            let itemKey = `dimensionErr${j}`;
            onSrchObj[
              itemKey
            ] = `@ondc/org/payload_details/dimensions is a required property in /search request for 'P2H2P' shipments`;
          }
        });
      });
    }
  } catch (error) {
    console.log(
      `!!Error while checking fulfillment ids in /items in ${constants.LOG_ONSEARCH} api`,
      error
    );
  }
  let providerLoc = false;
  // RGC checks on bpp/provider

  console.log(`Checking Reverse Geocoding on bpp/providers`);
  if (onSearch.hasOwnProperty("bpp/providers")) {
    const providers = onSearch["bpp/providers"];
    for (let i = 0; i < providers.length; i++) {
      const provider = providers[i];
      if (provider.hasOwnProperty("locations")) {
        const locations = provider.locations;
        if (locations?.length > 1) {
          providerLoc = true;
        }
        for (let j = 0; j < locations.length; j++) {
          const {
            id,
            gps,
            address: { area_code },
          } = locations[j];
          try {
            const [lat, long] = gps.split(",");
            const match = await reverseGeoCodingCheck(lat, long, area_code);
            if (!match) {
              onSrchObj[
                "bpp/provider:location:" + id + ":RGC"
              ] = `Reverse Geocoding for location ID ${id} failed. Area Code ${area_code} not matching with ${lat},${long} Lat-Long pair.`;
            }
          } catch (error) {
            console.log("bpp/providers error: ", error);
          }
        }
      }
      dao.setValue("providerLoc", providerLoc);
    }
  }

  return onSrchObj;
};
module.exports = checkOnSearch;
