/**
 * This function will only return true if the request was received between 8-5 UTC
 * 
 * @param {*} claims Incoming claims from Cloudflare Access
 * @returns boolean
 */
async function externalEvaluation(claims) {
  const now = new Date()
  const currentUTCHour = now.getHours()

  // If you want to use a specific time zone then you can do something like this. 
  // const currentHour = new Date(new Date().toLocaleString('en-US', {
  //   timeZone: 'America/New_York',
  // })).getHours()

  // Only allow someone to successfully login between 8-5 UTC
  return currentUTCHour >= 8 && currentUTCHour <= 17
}