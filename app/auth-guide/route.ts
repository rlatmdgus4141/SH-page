import {authGuide} from "@/lib/auth-guide";
export async function GET(){return new Response(authGuide,{headers:{"Content-Type":"text/plain; charset=utf-8","X-Content-Type-Options":"nosniff"}});}
